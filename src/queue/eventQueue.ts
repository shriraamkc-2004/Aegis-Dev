/**
 * Aegis Enterprise - Event Queue with BullMQ
 * Handles asynchronous event processing with backpressure
 */
import { Queue, Worker, Job } from 'bullmq';
import redis from '../redis/client';
import type { ConnectionOptions } from 'bullmq';

const bullConnection: ConnectionOptions = redis as any;

export interface EventJobData {
  event_type: string;
  source: string;
  timestamp: number;
  organization_id: number;
  raw_data?: Record<string, any>;
}

export interface DetectionJobData {
  organization_id: number;
  trigger_reason: string;
}

// Event processing queue
export const eventQueue = new Queue<EventJobData>('telemetry-events', {
  connection: bullConnection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000
    },
    removeOnComplete: 100,
    removeOnFail: 1000
  }
});

// Detection trigger queue
export const detectionQueue = new Queue<DetectionJobData>('detection-triggers', {
  connection: bullConnection,
  defaultJobOptions: {
    attempts: 2,
    backoff: {
      type: 'fixed',
      delay: 5000
    }
  }
});

// Event worker - processes incoming events
export const eventWorker = new Worker<EventJobData>(
  'telemetry-events',
  async (job: Job<EventJobData>) => {
    const { event_type, source, timestamp, organization_id, raw_data } = job.data;
    
    // Import Prisma client dynamically to avoid circular dependencies
    const { getPrismaClient } = await import('../saas/prisma_client.js');
    const prisma = getPrismaClient();
    
    try {
      await prisma.telemetryEvent.create({
        data: {
          event_type,
          source,
          timestamp: new Date(timestamp * 1000),
          organization_id,
          raw_data: raw_data || null
        }
      });
      
      // Check if we should trigger detection cycle
      const pendingCount = await eventQueue.getWaitingCount();
      if (pendingCount >= 50) {
        await detectionQueue.add('run-detection' as any, {
          organization_id,
          trigger_reason: 'batch_threshold'
        }, { priority: 1 });
      }
    } finally {
      await prisma.$disconnect();
    }
  },
  {
    connection: bullConnection,
    concurrency: 10
  }
);

// Detection worker - runs anomaly detection
export const detectionWorker = new Worker<DetectionJobData>(
  'detection-triggers',
  async (job: Job<DetectionJobData>) => {
    const { organization_id, trigger_reason } = job.data;
    console.log(`Running detection cycle for org ${organization_id} (reason: ${trigger_reason})`);
    
    // Import detection logic
    const { HybridDetector } = await import('../hybrid_detector');
    const detector = new HybridDetector({ iforestEnabled: true });
    
    // Run detection cycle
    // Import Prisma client dynamically to avoid circular dependencies
    const { getPrismaClient } = await import('../saas/prisma_client.js');
    const prisma = getPrismaClient();
    
    try {
      const cutoff = new Date(Date.now() - 60 * 1000); // Last 60 seconds
      const events = await prisma.telemetryEvent.findMany({
        where: {
          organization_id,
          timestamp: { gte: cutoff }
        },
        orderBy: { timestamp: 'asc' }
      });
      
      if (events.length === 0) return;
      
      // Calculate event rate
      const eventCount = events.length;
      const zScore = calculateZScore(eventCount, 50, 20); // mean=50, std=20
      
      if (zScore > 3.0) {
        // Run full hybrid analysis
        const result = await detector.analyze(zScore, eventCount, 60, 3.0);
        
        // Create anomaly record
        await prisma.anomaly.create({
          data: {
            organization_id,
            timestamp: new Date(),
            z_score: zScore,
            iforest_score: result.iforestScore,
            ewma_score: Math.abs(result.ewmaScore),
            hybrid_score: result.hybridScore,
            severity: result.hybridSeverity,
            event_count: eventCount,
            source_entropy: result.features?.sourceEntropy || 0,
            burst_ratio: result.features?.burstRatio || 0,
            status: 'PENDING',
            diagnosis: `Automated detection: ${result.detectionMethod}`,
            detection_method: result.detectionMethod
          }
        });
      }
    } finally {
      await prisma.$disconnect();
    }
  },
  {
    connection: bullConnection,
    concurrency: 2
  }
);

// Helper function to calculate Z-score
function calculateZScore(value: number, mean: number, std: number): number {
  if (std === 0) return 0;
  return (value - mean) / std;
}

// Queue a single event
export async function queueEvent(data: EventJobData) {
  await eventQueue.add('process-event' as any, data, {
    priority: data.event_type.includes('alert') ? 1 : 10
  });
}

// Queue batch events
export async function queueBatchEvents(events: EventJobData[]) {
  const jobs = events.map(e => ({
    name: 'process-event' as any,
    data: e,
    opts: { priority: e.event_type.includes('alert') ? 1 : 10 }
  }));
  
  await eventQueue.addBulk(jobs as any);
}

// Trigger detection cycle
export async function triggerDetection(organization_id: number, reason: string = 'manual') {
  await detectionQueue.add('run-detection' as any, {
    organization_id,
    trigger_reason: reason
  });
}

// Queue statistics
export async function getQueueStats() {
  const eventWaiting = await eventQueue.getWaitingCount();
  const eventActive = await eventQueue.getActiveCount();
  const detectionWaiting = await detectionQueue.getWaitingCount();
  
  return {
    events: {
      waiting: eventWaiting,
      active: eventActive
    },
    detection: {
      waiting: detectionWaiting
    }
  };
}

// Worker event handlers
eventWorker.on('completed', (job) => {
  console.log(`Event job ${job.id} completed`);
});

eventWorker.on('failed', (job, err) => {
  console.error(`Event job ${job?.id} failed:`, err);
});

detectionWorker.on('completed', (job) => {
  console.log(`Detection job ${job.id} completed`);
});

detectionWorker.on('failed', (job, err) => {
  console.error(`Detection job ${job?.id} failed:`, err);
});