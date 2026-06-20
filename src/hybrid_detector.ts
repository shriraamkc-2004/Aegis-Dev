/**
 * Aegis Hybrid Anomaly Detection Engine
 * 
 * Layer 1: Z-Score (fast, univariate spike detection — existing)
 * Layer 2: Isolation Forest (multivariate, non-parametric deep analysis)
 * Layer 3: EWMA (Exponentially Weighted Moving Average — adaptive trend)
 * 
 * All layers feed into a fused severity classifier.
 */

import { dbAll } from "./server_db.js";

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

/** Average path length c(n) for normalization — harmonic number approximation */
function averagePathLength(n: number): number {
  if (n <= 1) return 0;
  if (n === 2) return 1;
  const eulerGamma = 0.5772156649;
  return 2 * (Math.log(n - 1) + eulerGamma) - 2 * (n - 1) / n;
}

/** Build a single isolation tree recursively */
function buildTree(data: number[][], depth: number, maxDepth: number): ITreeNode {
  const n = data.length;

  // External node conditions
  if (depth >= maxDepth || n <= 1) {
    return { size: n, isExternal: true };
  }

  // Check if all points are identical
  const nFeatures = data[0].length;
  let allSame = true;
  for (let i = 1; i < n; i++) {
    for (let f = 0; f < nFeatures; f++) {
      if (data[i][f] !== data[0][f]) { allSame = false; break; }
    }
    if (!allSame) break;
  }
  if (allSame) {
    return { size: n, isExternal: true };
  }

  // Pick a random feature that has variance
  const featureOrder = Array.from({ length: nFeatures }, (_, i) => i);
  // Shuffle
  for (let i = featureOrder.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [featureOrder[i], featureOrder[j]] = [featureOrder[j], featureOrder[i]];
  }

  let splitFeature = -1;
  let minVal = 0, maxVal = 0;

  for (const f of featureOrder) {
    const vals = data.map(row => row[f]);
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

  // Random split value between min and max
  const splitValue = minVal + Math.random() * (maxVal - minVal);

  const leftData = data.filter(row => row[splitFeature] < splitValue);
  const rightData = data.filter(row => row[splitFeature] >= splitValue);

  // Safety: if split doesn't actually separate, make external
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

/** Compute path length for a single point through a tree */
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

  /** Train the forest on historical feature vectors */
  train(data: number[][]): void {
    if (data.length < 10) {
      // Not enough data to train
      this.trained = false;
      return;
    }

    this.trees = [];
    const sampleSize = Math.min(this.config.sampleSize, data.length);
    this.trainingSize = data.length;

    for (let t = 0; t < this.config.nTrees; t++) {
      // Sub-sample
      const sample: number[][] = [];
      for (let i = 0; i < sampleSize; i++) {
        sample.push(data[Math.floor(Math.random() * data.length)]);
      }
      this.trees.push(buildTree(sample, 0, this.config.maxDepth));
    }

    this.trained = true;
  }

  /** Score a single point — returns anomaly score in [0, 1]. Higher = more anomalous. */
  score(point: number[]): number {
    if (!this.trained || this.trees.length === 0) return 0;

    let avgPath = 0;
    for (const tree of this.trees) {
      avgPath += pathLength(point, tree, 0);
    }
    avgPath /= this.trees.length;

    const c = averagePathLength(this.config.sampleSize);
    if (c === 0) return 0;

    // Anomaly score: s(x, n) = 2^(-E(h(x)) / c(n))
    const score = Math.pow(2, -avgPath / c);
    return Math.max(0, Math.min(1, score));
  }

  /** Score multiple points */
  scoreAll(points: number[][]): number[] {
    return points.map(p => this.score(p));
  }

  isTrained(): boolean { return this.trained; }
  getTreeCount(): number { return this.trees.length; }
  getTrainingSize(): number { return this.trainingSize; }
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
  private alpha: number;      // Smoothing factor (0 < α <= 1). Higher = more reactive.
  private state: EWMAState;

  constructor(alpha: number = 0.15) {
    this.alpha = alpha;
    this.state = { mean: 0, variance: 0, std: 0, zScore: 0, initialized: false };
  }

  /** Update EWMA with a new observation and return current state */
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

    // Update mean: μ_t = α * x_t + (1 - α) * μ_{t-1}
    this.state.mean = this.alpha * value + (1 - this.alpha) * prevMean;

    // Update variance: σ²_t = (1 - α) * (σ²_{t-1} + α * diff²)
    this.state.variance = (1 - this.alpha) * (this.state.variance + this.alpha * diff * diff);
    this.state.std = Math.sqrt(this.state.variance);

    // EWMA Z-Score
    this.state.zScore = this.state.std > 0.001 ? (value - this.state.mean) / this.state.std : 0;

    return { ...this.state };
  }

  getState(): EWMAState { return { ...this.state }; }

  setAlpha(alpha: number): void {
    this.alpha = Math.max(0.01, Math.min(1.0, alpha));
  }

  reset(): void {
    this.state = { mean: 0, variance: 0, std: 0, zScore: 0, initialized: false };
  }
}

// ============================================================
// FEATURE EXTRACTOR — Multivariate feature vector from events
// ============================================================

export interface FeatureVector {
  eventsPerSec: number;
  sourceEntropy: number;
  uniqueSources: number;
  rateAcceleration: number;
  burstRatio: number;
  timestamp: number;
}

/** Shannon entropy of a distribution */
function shannonEntropy(counts: Record<string, number>): number {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  let entropy = 0;
  for (const count of Object.values(counts)) {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/** Extract a multivariate feature vector from recent events */
export async function extractFeatures(windowSec: number): Promise<FeatureVector> {
  const tNow = Date.now() / 1000;
  const cutoff = tNow - windowSec - 2;
  const currentSec = Math.floor(tNow);

  // Get per-second event counts
  const countRows = await dbAll<any>(
    "SELECT CAST(timestamp as INTEGER) as sec, COUNT(*) as count FROM events WHERE timestamp >= ? GROUP BY sec ORDER BY sec DESC",
    [cutoff]
  );
  const countsMap: Record<number, number> = {};
  countRows.forEach((r: any) => { countsMap[r.sec] = r.count; });

  const eventsPerSec = countsMap[currentSec] || 0;

  // Rate acceleration (difference between current and 5-sec avg)
  let recentAvg = 0;
  for (let i = 1; i <= 5; i++) recentAvg += (countsMap[currentSec - i] || 0);
  recentAvg /= 5;
  const rateAcceleration = eventsPerSec - recentAvg;

  // Burst ratio: max/min in last 10 seconds
  let maxRate = 0, minRate = Infinity;
  for (let i = 0; i < 10; i++) {
    const c = countsMap[currentSec - i] || 0;
    if (c > maxRate) maxRate = c;
    if (c < minRate) minRate = c;
  }
  const burstRatio = minRate > 0 ? maxRate / minRate : maxRate;

  // Source entropy and unique sources (last 15 seconds)
  const sourceRows = await dbAll<any>(
    "SELECT source, COUNT(*) as cnt FROM events WHERE timestamp >= ? GROUP BY source",
    [tNow - 15]
  );
  const sourceCounts: Record<string, number> = {};
  sourceRows.forEach((r: any) => { sourceCounts[r.source] = r.cnt; });
  const sourceEntropy = shannonEntropy(sourceCounts);
  const uniqueSources = Object.keys(sourceCounts).length;

  return {
    eventsPerSec,
    sourceEntropy,
    uniqueSources,
    rateAcceleration,
    burstRatio,
    timestamp: tNow,
  };
}

/** Convert FeatureVector to a numeric array for iForest */
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
// HYBRID DETECTOR — Orchestrates all 3 layers + fusion
// ============================================================

export interface HybridResult {
  // Layer 1: Z-Score (existing, passed in)
  zScore: number;
  zScoreSeverity: string;

  // Layer 2: Isolation Forest
  iforestScore: number;
  iforestActive: boolean;
  iforestTrained: boolean;
  iforestTreeCount: number;

  // Layer 3: EWMA
  ewmaScore: number;
  ewmaMean: number;
  ewmaStd: number;

  // Fused
  hybridScore: number;
  hybridSeverity: string;
  detectionMethod: string;

  // Feature vector (for logging)
  features: FeatureVector | null;
}

export class HybridDetector {
  private iforest: IsolationForest;
  private ewma: EWMADetector;
  private featureHistory: FeatureVector[] = [];
  private maxHistory = 300; // Keep last 300 feature vectors (~5 min at 1/sec)
  private retrainInterval = 30; // Retrain iForest every 30 seconds
  private tickCount = 0;
  private iforestEnabled: boolean;
  private ewmaAlpha: number;
  private fusionWeights: { zscore: number; iforest: number; ewma: number };

  constructor(opts: {
    iforestEnabled?: boolean;
    ewmaAlpha?: number;
    fusionWeights?: { zscore: number; iforest: number; ewma: number };
  } = {}) {
    this.iforest = new IsolationForest({ nTrees: 50, sampleSize: 128, maxDepth: 8 });
    this.ewma = new EWMADetector(opts.ewmaAlpha || 0.15);
    this.iforestEnabled = opts.iforestEnabled ?? true;
    this.ewmaAlpha = opts.ewmaAlpha || 0.15;
    this.fusionWeights = opts.fusionWeights || { zscore: 0.35, iforest: 0.40, ewma: 0.25 };
  }

  /** Main analysis function — called every second from detector loop */
  async analyze(
    zScore: number,
    currentRate: number,
    windowSec: number,
    zScoreThreshold: number,
  ): Promise<HybridResult> {
    this.tickCount++;

    // --- Layer 1: Z-Score severity (existing logic) ---
    let zScoreSeverity = "LOW";
    if (zScore > zScoreThreshold * 2) zScoreSeverity = "CRITICAL";
    else if (zScore > zScoreThreshold * 1.5) zScoreSeverity = "HIGH";
    else if (zScore > zScoreThreshold) zScoreSeverity = "MEDIUM";

    // --- Layer 2: Isolation Forest ---
    let iforestScore = 0;
    let features: FeatureVector | null = null;

    if (this.iforestEnabled) {
      // Extract features every second
      try {
        features = await extractFeatures(windowSec);
        this.featureHistory.push(features);
        if (this.featureHistory.length > this.maxHistory) {
          this.featureHistory = this.featureHistory.slice(-this.maxHistory);
        }
      } catch (e: any) {
        // Feature extraction failed — skip iForest this tick
      }

      // Retrain periodically
      if (this.tickCount % this.retrainInterval === 0 && this.featureHistory.length >= 30) {
        const trainingData = this.featureHistory.map(fv => featureVectorToArray(fv));
        this.iforest.train(trainingData);
      }

      // Score current point
      if (features && this.iforest.isTrained()) {
        iforestScore = this.iforest.score(featureVectorToArray(features));
      }
    }

    // --- Layer 3: EWMA ---
    const ewmaState = this.ewma.update(currentRate);
    const ewmaScore = Math.abs(ewmaState.zScore); // Use absolute value for scoring

    // --- Fused Scoring ---
    // Normalize all scores to [0, 1] range
    const zNorm = Math.min(zScore / (zScoreThreshold * 3), 1); // Z normalized against 3x threshold
    const iNorm = iforestScore; // Already [0, 1]
    const eNorm = Math.min(ewmaScore / 6, 1); // EWMA Z normalized against 6 SD

    let hybridScore: number;
    let detectionMethod: string;

    if (this.iforestEnabled && this.iforest.isTrained()) {
      // Full hybrid: weighted sum of all 3 layers
      const w = this.fusionWeights;
      hybridScore = w.zscore * zNorm + w.iforest * iNorm + w.ewma * eNorm;
      detectionMethod = "HYBRID";
    } else if (this.iforestEnabled && !this.iforest.isTrained()) {
      // Warming up: Z-Score + EWMA only
      hybridScore = 0.6 * zNorm + 0.4 * eNorm;
      detectionMethod = "ZSCORE+EWMA";
    } else {
      // iForest disabled: Z-Score + EWMA
      hybridScore = 0.7 * zNorm + 0.3 * eNorm;
      detectionMethod = "ZSCORE+EWMA";
    }

    // Hybrid severity classification
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

  /** Update configuration at runtime */
  setConfig(opts: { iforestEnabled?: boolean; ewmaAlpha?: number; fusionWeights?: { zscore: number; iforest: number; ewma: number } }): void {
    if (opts.iforestEnabled !== undefined) this.iforestEnabled = opts.iforestEnabled;
    if (opts.ewmaAlpha !== undefined) {
      this.ewmaAlpha = opts.ewmaAlpha;
      this.ewma.setAlpha(opts.ewmaAlpha);
    }
    if (opts.fusionWeights) this.fusionWeights = opts.fusionWeights;
  }

  /** Get engine status for health/metrics API */
  getStatus(): { iforestTrained: boolean; iforestTrees: number; iforestTrainingSize: number; ewmaInitialized: boolean; featureHistoryLength: number; tickCount: number } {
    return {
      iforestTrained: this.iforest.isTrained(),
      iforestTrees: this.iforest.getTreeCount(),
      iforestTrainingSize: this.iforest.getTrainingSize(),
      ewmaInitialized: this.ewma.getState().initialized,
      featureHistoryLength: this.featureHistory.length,
      tickCount: this.tickCount,
    };
  }

  /** Reset all state (for demo restart) */
  reset(): void {
    this.iforest = new IsolationForest({ nTrees: 50, sampleSize: 128, maxDepth: 8 });
    this.ewma.reset();
    this.featureHistory = [];
    this.tickCount = 0;
  }
}
