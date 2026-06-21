/**
 * Aegis Enterprise - Hybrid Detector Unit Tests
 * Tests for the core anomaly detection engine
 */
import { HybridDetector, IsolationForest } from '../../src/hybrid_detector.js';

// Mock the server_db module to avoid database dependency in unit tests
jest.mock('../../src/server_db.js', () => ({
  dbAll: jest.fn().mockResolvedValue([]),
  dbGet: jest.fn().mockResolvedValue(null),
  dbRun: jest.fn().mockResolvedValue({ changes: 0 }),
}));

describe('HybridDetector', () => {
  let detector: HybridDetector;

  beforeEach(() => {
    detector = new HybridDetector({ 
      iforestEnabled: true,
    });
  });

  describe('analyze()', () => {
    it('should detect CRITICAL severity when z-score > 6', async () => {
      const result = await detector.analyze(7.0, 100, 60, 3.0);
      
      expect(result.zScore).toBe(7.0);
      expect(result.zScoreSeverity).toBe('CRITICAL');
      expect(result.hybridSeverity).toBe('CRITICAL');
      expect(result.hybridScore).toBeGreaterThanOrEqual(0.7);
    });

    it('should detect HIGH severity when z-score > 4.5', async () => {
      const result = await detector.analyze(5.0, 100, 60, 3.0);
      
      expect(result.zScore).toBe(5.0);
      expect(result.zScoreSeverity).toBe('HIGH');
      expect(result.hybridScore).toBeGreaterThanOrEqual(0.5);
      expect(result.hybridScore).toBeLessThan(0.7);
    });

    it('should detect MEDIUM severity when z-score > 3', async () => {
      const result = await detector.analyze(3.5, 100, 60, 3.0);
      
      expect(result.zScore).toBe(3.5);
      expect(result.zScoreSeverity).toBe('MEDIUM');
      expect(result.hybridScore).toBeGreaterThanOrEqual(0.3);
      expect(result.hybridScore).toBeLessThan(0.5);
    });

    it('should detect LOW severity when z-score < 3', async () => {
      const result = await detector.analyze(2.0, 50, 60, 3.0);
      
      expect(result.zScore).toBe(2.0);
      expect(result.zScoreSeverity).toBe('LOW');
      expect(result.hybridScore).toBeLessThan(0.3);
    });

    it('should return detection method as ZSCORE+EWMA when iforest disabled', async () => {
      const detectorZscoreOnly = new HybridDetector({ 
        iforestEnabled: false,
      });
      
      const result = await detectorZscoreOnly.analyze(4.0, 100, 60, 3.0);
      
      expect(result.detectionMethod).toBe('ZSCORE+EWMA');
    });

    it('should return detection method as ZSCORE+EWMA when iforest not yet trained', async () => {
      // iForest is enabled but not trained (no feature history)
      const result = await detector.analyze(4.0, 100, 60, 3.0);
      
      // Should be ZSCORE+EWMA since iforest needs 30+ ticks to train
      expect(result.detectionMethod).toBe('ZSCORE+EWMA');
    });

    it('should calculate EWMA score correctly', async () => {
      const result = await detector.analyze(4.0, 100, 60, 3.0);
      
      expect(result.ewmaScore).toBeDefined();
      expect(typeof result.ewmaScore).toBe('number');
    });

    it('should include EWMA mean and std in results', async () => {
      const result = await detector.analyze(4.0, 100, 60, 3.0);
      
      expect(result.ewmaMean).toBeDefined();
      expect(result.ewmaStd).toBeDefined();
    });
  });

  describe('setConfig()', () => {
    it('should disable Isolation Forest at runtime', async () => {
      detector.setConfig({ iforestEnabled: false });
      
      const result = await detector.analyze(4.0, 100, 60, 3.0);
      
      expect(result.iforestScore).toBe(0);
      expect(result.detectionMethod).toBe('ZSCORE+EWMA');
    });

    it('should update fusion weights at runtime', async () => {
      detector.setConfig({ fusionWeights: { zscore: 1.0, iforest: 0, ewma: 0 } });
      
      // With 100% z-score weight, score should be purely z-based
      const result = await detector.analyze(4.0, 100, 60, 3.0);
      
      expect(result.detectionMethod).toBeDefined();
    });
  });

  describe('getStatus()', () => {
    it('should return engine status information', () => {
      const status = detector.getStatus();
      
      expect(status.iforestTrained).toBe(false);
      expect(status.iforestTrees).toBe(0);
      expect(status.ewmaInitialized).toBe(false);
      expect(status.featureHistoryLength).toBe(0);
      expect(status.tickCount).toBe(0);
    });

    it('should increment tick count after analyze', async () => {
      await detector.analyze(4.0, 100, 60, 3.0);
      
      const status = detector.getStatus();
      expect(status.tickCount).toBe(1);
    });
  });

  describe('reset()', () => {
    it('should reset all state', async () => {
      await detector.analyze(4.0, 100, 60, 3.0);
      detector.reset();
      
      const status = detector.getStatus();
      expect(status.tickCount).toBe(0);
      expect(status.featureHistoryLength).toBe(0);
      expect(status.iforestTrained).toBe(false);
      expect(status.ewmaInitialized).toBe(false);
    });
  });
});

describe('IsolationForest', () => {
  let iforest: IsolationForest;

  beforeEach(() => {
    iforest = new IsolationForest({
      nTrees: 50,
      sampleSize: 128,
      maxDepth: 8
    });
  });

  describe('train()', () => {
    it('should train on sample data', () => {
      const data = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);

      iforest.train(data);

      expect(iforest.isTrained()).toBe(true);
    });

    it('should not be trained with insufficient data', () => {
      // Less than 10 points
      const data = [[1, 2], [3, 4], [5, 6]];
      iforest.train(data);

      expect(iforest.isTrained()).toBe(false);
    });

    it('should report correct tree count after training', () => {
      const data = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);

      iforest.train(data);

      expect(iforest.getTreeCount()).toBe(50);
    });
  });

  describe('score()', () => {
    it('should return anomaly scores for data points', () => {
      const trainData = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);
      iforest.train(trainData);

      const scores = iforest.scoreAll([[50, 50], [150, 150], [-50, -50]]);

      expect(scores).toHaveLength(3);
      expect(scores.every(s => typeof s === 'number')).toBe(true);
    });

    it('should return 0 when not trained', () => {
      const score = iforest.score([50, 50]);
      expect(score).toBe(0);
    });

    it('should give higher scores to outliers', () => {
      // Train on normal data centered around 50
      const trainData = Array.from({ length: 200 }, () => [
        50 + (Math.random() - 0.5) * 20,
        50 + (Math.random() - 0.5) * 20
      ]);
      iforest.train(trainData);

      // Normal point
      const normalScore = iforest.score([50, 50]);
      // Outlier point
      const outlierScore = iforest.score([200, 200]);

      expect(outlierScore).toBeGreaterThan(normalScore);
    });

    it('should return scores in [0, 1] range', () => {
      const trainData = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);
      iforest.train(trainData);

      const score = iforest.score([50, 50]);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(1);
    });
  });

  describe('scoreAll()', () => {
    it('should score multiple points', () => {
      const trainData = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);
      iforest.train(trainData);

      const scores = iforest.scoreAll([[10, 10], [50, 50], [90, 90]]);
      expect(scores).toHaveLength(3);
    });
  });

  describe('getTrainingSize()', () => {
    it('should return 0 when not trained', () => {
      expect(iforest.getTrainingSize()).toBe(0);
    });

    it('should return training data size after training', () => {
      const data = Array.from({ length: 100 }, () => [
        Math.random() * 100,
        Math.random() * 100
      ]);
      iforest.train(data);

      expect(iforest.getTrainingSize()).toBe(100);
    });
  });
});
