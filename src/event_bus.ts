/**
 * Aegis Enterprise — Internal Event Bus
 *
 * Provides a lightweight, asynchronous pub-sub hub for distributing
 * anomaly events, incident alerts, and telemetry updates to decoupled subscribers.
 */

export type EventBusCallback<T = any> = (data: T) => void | Promise<void>;

export class EventBus {
  private static instance: EventBus;
  private subscribers: Map<string, Set<EventBusCallback>> = new Map();

  private constructor() {}

  public static getInstance(): EventBus {
    if (!EventBus.instance) {
      EventBus.instance = new EventBus();
    }
    return EventBus.instance;
  }

  /** Subscribe to a channel */
  subscribe<T = any>(
    channel: string,
    callback: EventBusCallback<T>,
  ): () => void {
    if (!this.subscribers.has(channel)) {
      this.subscribers.set(channel, new Set());
    }
    this.subscribers.get(channel)!.add(callback);

    // Return an unsubscribe handler
    return () => {
      const subs = this.subscribers.get(channel);
      if (subs) {
        subs.delete(callback);
        if (subs.size === 0) {
          this.subscribers.delete(channel);
        }
      }
    };
  }

  /** Publish data to all subscribers on a channel asynchronously */
  publish<T = any>(channel: string, data: T): void {
    const subs = this.subscribers.get(channel);
    if (!subs || subs.size === 0) return;

    for (const callback of subs) {
      // Execute asynchronously to ensure non-blocking pipeline
      setImmediate(async () => {
        try {
          await callback(data);
        } catch (err: any) {
          console.error(
            `[EventBus] Subscriber error on channel "${channel}":`,
            err.message,
          );
        }
      });
    }
  }
}

export const eventBus = EventBus.getInstance();
