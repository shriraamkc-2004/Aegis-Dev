import { logStructured, requestLoggerMiddleware } from '../../src/observability/logger.js';
import { Request, Response } from 'express';

jest.mock('uuid', () => ({
  v4: () => 'mocked-uuid'
}));

describe('Logger Observability', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('should format structured logs as valid JSON', () => {
    logStructured('info', 'Test log message', { traceId: '123', requestId: '456' });
    expect(consoleSpy).toHaveBeenCalled();
    const output = consoleSpy.mock.calls[0][0];
    const logData = JSON.parse(output);
    expect(logData.level).toBe('info');
    expect(logData.message).toBe('Test log message');
    expect(logData.traceId).toBe('123');
    expect(logData.requestId).toBe('456');
    expect(logData.timestamp).toBeDefined();
  });

  it('should inject trace and request headers in requestLoggerMiddleware', () => {
    const req: Partial<Request> = {
      headers: {},
      method: 'GET',
      originalUrl: '/test-url'
    };
    const res: Partial<Response> = {
      setHeader: jest.fn(),
      on: jest.fn()
    };
    const next = jest.fn();

    requestLoggerMiddleware(req as Request, res as Response, next);

    expect(next).toHaveBeenCalled();
    expect((req as any).requestId).toBeDefined();
    expect((req as any).traceId).toBeDefined();
    expect(res.setHeader).toHaveBeenCalledWith('x-request-id', (req as any).requestId);
    expect(res.setHeader).toHaveBeenCalledWith('x-trace-id', (req as any).traceId);
  });
});
