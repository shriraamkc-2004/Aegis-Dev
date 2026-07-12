/**
 * Aegis Hybrid Anomaly Detection Engine — Real-Time Refactored
 *
 * Layer 1: Z-Score (real-time rolling)
 * Layer 2: Isolation Forest (inference per event, background retrained)
 * Layer 3: EWMA (Exponentially Weighted Moving Average — per event adaptive trend)
 *
 * Uses the Real-Time Context Engine for zero-I/O in-memory feature extraction.
 */

import { contextEngine } from "./copilot/rolling_context.js";
import { detectionOrchestrator } from "./detection_orchestrator.js";
import {
  RuleEngineModule,
  IsolationForestModule,
  BehavioralEngineModule,
  RiskEngineModule,
} from "./detection/modules.js";

// ============================================================
// ISOLATION FOREST — Pure TypeScript Implementation
// ============================================================

interface ITreeNode {
  left?: ITreeNode;
  right?: ITreeNode;
  splitFeature?: number;
  splitValue?: number;
  size: number;
  isExternal: boolean;
}

interface IsolationForestConfig {
  nTrees: number;
  sampleSize: number;
  maxDepth: number;
}

const DEFAULT_IFOREST_CONFIG: IsolationForestConfig = {
  nTrees: 50,
  sampleSize: 128,
  maxDepth: 8,
};

function averagePathLength(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const eulerGamma = 0.5772156649;
  return 2 * (Math.log(n - 1) + eulerGamma) - (2 * (n - 1)) / n;
}

function buildTree(
  data: number[][],
  depth: number,
  maxDepth: number,
): ITreeNode {
  const n = data.length;

  if (depth >= maxDepth || n <= 1) {
    return { size: n, isExternal: true };
  }

  const nFeatures = data[0].length;
  let allSame = true;
  for (let i = 1; i < n; i++) {
    for (let f = 0; f < nFeatures; f++) {
      if (data[i][f] !== data[0][f]) {
        allSame = false;
        break;
      }
    }
    if (!allSame) break;
  }
  if (allSame) {
    return { size: n, isExternal: true };
  }

  const featureOrder = Array.from({ length: nFeatures }, (_, i) => i);
  for (let i = featureOrder.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [featureOrder[i], featureOrder[j]] = [featureOrder[j], featureOrder[i]];
  }

  let splitFeature = -1;
  let minVal = 0,
    maxVal = 0;

  for (const f of featureOrder) {
    const vals = data.map((row) => row[f]);
    minVal = Math.min(...vals);
    maxVal = Math.max(...vals);
    if (maxVal > minVal) {
      splitFeature = f;
      break;
    }
  }

  if (splitFeature === -1) {
    return { size: n, isExternal: true };
  }

  const splitValue = minVal + Math.random() * (maxVal - minVal);

  const leftData = data.filter((row) => row[splitFeature] < splitValue);
  const rightData = data.filter((row) => row[splitFeature] >= splitValue);

  if (leftData.length === 0 || rightData.length === 0) {
    return { size: n, isExternal: true };
  }

  return {
    splitFeature,
    splitValue,
    size: n,
    isExternal: false,
    left: buildTree(leftData, depth + 1, maxDepth),
    right: buildTree(rightData, depth + 1, maxDepth),
  };
}

function pathLength(point: number[], node: ITreeNode, depth: number): number {
  if (node.isExternal) {
    return depth + averagePathLength(node.size);
  }

  if (point[node.splitFeature!] < node.splitValue!) {
    return pathLength(point, node.left!, depth + 1);
  } else {
    return pathLength(point, node.right!, depth + 1);
  }
}

export class IsolationForest {
  private trees: ITreeNode[] = [];
  private config: IsolationForestConfig;
  private trained = false;
  private trainingSize = 0;

  constructor(config: Partial<IsolationForestConfig> = {}) {
    this.config = { ...DEFAULT_IFOREST_CONFIG, ...config };
  }

  train(data: number[][]): void {
    if (data.length < 10) {
      this.trained = false;
      return;
    }

    this.trees = [];
    const sampleSize = Math.min(this.config.sampleSize, data.length);
    this.trainingSize = data.length;

    for (let t = 0; t < this.config.nTrees; t++) {
      const sample: number[][] = [];
      for (let i = 0; i < sampleSize; i++) {
        sample.push(data[Math.floor(Math.random() * data.length)]);
      }
      this.trees.push(buildTree(sample, 0, this.config.maxDepth));
    }

    this.trained = true;
  }

  score(point: number[]): number {
    if (!this.trained || this.trees.length === 0) return 0;

    let avgPath = 0;
    for (const tree of this.trees) {
      avgPath += pathLength(point, tree, 0);
    }
    avgPath /= this.trees.length;

    const c = averagePathLength(this.config.sampleSize);
    if (c === 0) return 0;

    const score = Math.pow(2, -avgPath / c);
    return Math.max(0, Math.min(1, score));
  }

  scoreAll(points: number[][]): number[] {
    return points.map((p) => this.score(p));
  }

  isTrained(): boolean {
    return this.trained;
  }
  getTreeCount(): number {
    return this.trees.length;
  }
  getTrainingSize(): number {
    return this.trainingSize;
  }
}

// ============================================================
// EWMA — Exponentially Weighted Moving Average
// ============================================================

export interface EWMAState {
  mean: number;
  variance: number;
  std: number;
  zScore: number;
  initialized: boolean;
}

export class EWMADetector {
  private alpha: number;
  private state: EWMAState;

  constructor(alpha: number = 0.15) {
    this.alpha = alpha;
    this.state = {
      mean: 0,
      variance: 0,
      std: 0,
      zScore: 0,
      initialized: false,
    };
  }

  update(value: number): EWMAState {
    if (!this.state.initialized) {
      this.state.mean = value;
      this.state.variance = 0;
      this.state.std = 0;
      this.state.zScore = 0;
      this.state.initialized = true;
      return { ...this.state };
    }

    const prevMean = this.state.mean;
    const diff = value - prevMean;

    this.state.mean = this.alpha * value + (1 - this.alpha) * prevMean;
    this.state.variance =
      (1 - this.alpha) * (this.state.variance + this.alpha * diff * diff);
    this.state.std = Math.sqrt(this.state.variance);
    this.state.zScore =
      this.state.std > 0.001 ? (value - this.state.mean) / this.state.std : 0;

    return { ...this.state };
  }

  getState(): EWMAState {
    return { ...this.state };
  }
  setAlpha(alpha: number): void {
    this.alpha = Math.max(0.01, Math.min(1.0, alpha));
  }
  reset(): void {
    this.state = {
      mean: 0,
      variance: 0,
      std: 0,
      zScore: 0,
      initialized: false,
    };
  }
}

// ============================================================
// FEATURE EXTRACTOR — Real-Time zero-I/O from Context Engine
// ============================================================

export interface FeatureVector {
  eventsPerSec: number;
  sourceEntropy: number;
  uniqueSources: number;
  rateAcceleration: number;
  burstRatio: number;
  timestamp: number;
}

export function extractFeaturesRealTime(windowSec: number): FeatureVector {
  const eventsPerSec = contextEngine.getGlobalRate(windowSec);
  const sourceEntropy = contextEngine.getSourceEntropy(windowSec);
  const uniqueSources = contextEngine.getUniqueSourcesCount(windowSec);
  const burstRatio = contextEngine.getBurstRatio(windowSec);

  // Rate acceleration compared to last 5 seconds
  const recentRate5s = contextEngine.getGlobalRate(5);
  const rateAcceleration = eventsPerSec - recentRate5s;

  return {
    eventsPerSec,
    sourceEntropy,
    uniqueSources,
    rateAcceleration,
    burstRatio,
    timestamp: Date.now() / 1000,
  };
}

export function featureVectorToArray(fv: FeatureVector): number[] {
  return [
    fv.eventsPerSec,
    fv.sourceEntropy,
    fv.uniqueSources,
    fv.rateAcceleration,
    fv.burstRatio,
  ];
}

// ============================================================
// HYBRID DETECTOR & THREAT FUSION ENGINE
// ============================================================

export interface HybridResult {
  zScore: number;
  zScoreSeverity: string;
  iforestScore: number;
  iforestActive: boolean;
  iforestTrained: boolean;
  iforestTreeCount: number;
  ewmaScore: number;
  ewmaMean: number;
  ewmaStd: number;
  hybridScore: number;
  hybridSeverity: string;
  detectionMethod: string;
  features: FeatureVector | null;
}

export class HybridDetector {
  private iforest: IsolationForest;
  private ewma: EWMADetector;
  private featureHistory: FeatureVector[] = [];
  private maxHistory = 500; // In-memory ring buffer size for training
  private retrainInterval = 500; // Asynchronous training every 500 events
  private processedEventsCount = 0;
  private iforestEnabled: boolean;
  private ewmaAlpha: number;
  private fusionWeights: { zscore: number; iforest: number; ewma: number };

  constructor(
    opts: {
      iforestEnabled?: boolean;
      ewmaAlpha?: number;
      fusionWeights?: { zscore: number; iforest: number; ewma: number };
    } = {},
  ) {
    this.iforest = new IsolationForest({
      nTrees: 50,
      sampleSize: 128,
      maxDepth: 8,
    });
    this.ewma = new EWMADetector(opts.ewmaAlpha || 0.15);
    this.iforestEnabled = opts.iforestEnabled ?? true;
    this.ewmaAlpha = opts.ewmaAlpha || 0.15;
    this.fusionWeights = opts.fusionWeights || {
      zscore: 0.35,
      iforest: 0.4,
      ewma: 0.25,
    };

    // Register modular engines in Orchestrator sequencing
    detectionOrchestrator.registerModule(new RuleEngineModule());
    detectionOrchestrator.registerModule(
      new IsolationForestModule(this.iforest),
    );
    detectionOrchestrator.registerModule(new BehavioralEngineModule());
    detectionOrchestrator.registerModule(new RiskEngineModule());
  }

  /**
   * Main real-time event analyzer.
   * Performs inline calculation and threat fusion for an incoming event.
   */
  async analyzeEvent(
    event: { event_type: string; source: string; timestamp: number },
    windowSec: number,
    zScoreThreshold: number,
  ): Promise<HybridResult> {
    this.processedEventsCount++;

    // 1. Record event in Context Engine
    contextEngine.addEvent(event);

    // 2. In-memory Real-Time Feature Engineering
    const features = extractFeaturesRealTime(windowSec);
    this.featureHistory.push(features);
    if (this.featureHistory.length > this.maxHistory) {
      this.featureHistory = this.featureHistory.slice(-this.maxHistory);
    }

    // 2.5 Run Detection Orchestrator sequential modules
    const moduleResults = await detectionOrchestrator.execute(event, features);

    // 3. Periodic Asynchronous retraining trigger (doesn't block event thread)
    if (
      this.processedEventsCount % this.retrainInterval === 0 &&
      this.featureHistory.length >= 30
    ) {
      const trainingData = this.featureHistory.map((fv) =>
        featureVectorToArray(fv),
      );
      // Run train synchronously or offload to next tick to keep thread hot
      process.nextTick(() => {
        try {
          this.iforest.train(trainingData);
        } catch (err) {
          // Graceful model train failure protection
        }
      });
    }

    // 4. Compute scoring components
    const currentRate = features.eventsPerSec;

    // Calculate rolling Z-Score based on history
    let zScore = 0;
    if (this.featureHistory.length > 5) {
      const rates = this.featureHistory.map((h) => h.eventsPerSec);
      const sum = rates.reduce((a, b) => a + b, 0);
      const mean = sum / rates.length;
      const sqSum = rates.reduce(
        (acc, val) => acc + Math.pow(val - mean, 2),
        0,
      );
      const stdDev = Math.sqrt(sqSum / (rates.length - 1));
      zScore = stdDev > 0 ? (currentRate - mean) / stdDev : 0;
    }

    let zScoreSeverity = "LOW";
    if (zScore > zScoreThreshold * 2) zScoreSeverity = "CRITICAL";
    else if (zScore > zScoreThreshold * 1.5) zScoreSeverity = "HIGH";
    else if (zScore > zScoreThreshold) zScoreSeverity = "MEDIUM";

    let iforestScore = 0;
    if (this.iforestEnabled && this.iforest.isTrained()) {
      iforestScore = this.iforest.score(featureVectorToArray(features));
    }

    const ewmaState = this.ewma.update(currentRate);
    const ewmaScore = Math.abs(ewmaState.zScore);

    // 5. Threat Fusion
    const zNorm = Math.min(zScore / (zScoreThreshold * 3), 1);
    const iNorm = iforestScore;
    const eNorm = Math.min(ewmaScore / 6, 1);

    let hybridScore: number;
    let detectionMethod: string;

    if (this.iforestEnabled && this.iforest.isTrained()) {
      const w = this.fusionWeights;
      hybridScore = w.zscore * zNorm + w.iforest * iNorm + w.ewma * eNorm;
      detectionMethod = "HYBRID";
    } else {
      hybridScore = 0.6 * zNorm + 0.4 * eNorm;
      detectionMethod = "ZSCORE+EWMA";
    }

    let hybridSeverity = "LOW";
    if (hybridScore >= 0.7) hybridSeverity = "CRITICAL";
    else if (hybridScore >= 0.5) hybridSeverity = "HIGH";
    else if (hybridScore >= 0.3) hybridSeverity = "MEDIUM";

    return {
      zScore,
      zScoreSeverity,
      iforestScore,
      iforestActive: this.iforestEnabled,
      iforestTrained: this.iforest.isTrained(),
      iforestTreeCount: this.iforest.getTreeCount(),
      ewmaScore: ewmaState.zScore,
      ewmaMean: ewmaState.mean,
      ewmaStd: ewmaState.std,
      hybridScore,
      hybridSeverity,
      detectionMethod,
      features,
    };
  }

  setConfig(opts: {
    iforestEnabled?: boolean;
    ewmaAlpha?: number;
    fusionWeights?: { zscore: number; iforest: number; ewma: number };
  }): void {
    if (opts.iforestEnabled !== undefined)
      this.iforestEnabled = opts.iforestEnabled;
    if (opts.ewmaAlpha !== undefined) {
      this.ewmaAlpha = opts.ewmaAlpha;
      this.ewma.setAlpha(opts.ewmaAlpha);
    }
    if (opts.fusionWeights) this.fusionWeights = opts.fusionWeights;
  }

  getStatus(): {
    iforestTrained: boolean;
    iforestTrees: number;
    iforestTrainingSize: number;
    ewmaInitialized: boolean;
    featureHistoryLength: number;
    processedEventsCount: number;
  } {
    return {
      iforestTrained: this.iforest.isTrained(),
      iforestTrees: this.iforest.getTreeCount(),
      iforestTrainingSize: this.iforest.getTrainingSize(),
      ewmaInitialized: this.ewma.getState().initialized,
      featureHistoryLength: this.featureHistory.length,
      processedEventsCount: this.processedEventsCount,
    };
  }

  reset(): void {
    this.iforest = new IsolationForest({
      nTrees: 50,
      sampleSize: 128,
      maxDepth: 8,
    });
    this.ewma.reset();
    this.featureHistory = [];
    this.processedEventsCount = 0;
  }
}
