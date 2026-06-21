/**
 * Aegis Enterprise - WebSocket Server with Socket.IO
 * Real-time event broadcasting and client communication
 */
import { Server as HttpServer } from 'http';
import { Server, Socket } from 'socket.io';
import { verifyToken } from '../auth.js';
import redis from '../redis/client.js';

let io: Server;

export interface AuthSocket extends Socket {
  data: {
    user: {
      id: number;
      username: string;
      role: string;
      organization_id: number;
    };
  };
}

export interface RealtimeEvent {
  type: string;
  data: any;
  timestamp: number;
}

/**
 * Setup WebSocket server with Socket.IO
 */
export function setupWebSocket(httpServer: HttpServer) {
  io = new Server(httpServer, {
    cors: {
      origin: process.env.FRONTEND_URL || 'http://localhost:5173',
      credentials: true,
      methods: ['GET', 'POST']
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    transports: ['websocket', 'polling']
  });

  // Authentication middleware
  io.use((socket: AuthSocket, next) => {
    const token = socket.handshake.auth.token;
    
    if (!token) {
      // Allow connection for demo mode without auth
      const mode = socket.handshake.auth.mode;
      if (mode === 'demo') {
        socket.data.user = {
          id: 0,
          username: 'demo_user',
          role: 'demo_admin',
          organization_id: 1
        };
        return next();
      }
      return next(new Error('Authentication required'));
    }

    try {
      const user = verifyToken(token);
      socket.data.user = user;
      next();
    } catch (error) {
      next(new Error('Invalid token'));
    }
  });

  // Connection handler
  io.on('connection', (socket: AuthSocket) => {
    const user = socket.data.user;
    console.log(`🔌 User ${user.username} connected (role: ${user.role})`);

    // Join organization room
    socket.join(`org:${user.organization_id}`);
    console.log(`   Joined room: org:${user.organization_id}`);

    // Join role-based room
    socket.join(`role:${user.role}`);
    console.log(`   Joined room: role:${user.role}`);

    // Join user-specific room
    socket.join(`user:${user.id}`);

    // Send welcome message with connection info
    socket.emit('connected', {
      message: 'Connected to Aegis WebSocket server',
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      },
      timestamp: Date.now()
    });

    // Handle custom events
    socket.on('acknowledge_alert', async (data: { anomalyId: number }) => {
      console.log(`Alert acknowledged: #${data.anomalyId}`);
      
      // Broadcast to all users in organization
      socket.to(`org:${user.organization_id}`).emit('alert_acknowledged', {
        anomalyId: data.anomalyId,
        acknowledgedBy: user.username,
        timestamp: Date.now()
      });
    });

    socket.on('update_incident', async (data: { incidentId: number; status: string }) => {
      console.log(`Incident updated: #${data.incidentId} -> ${data.status}`);
      
      // Broadcast to SOC analysts and org admins
      socket.to(`role:soc_analyst`).emit('incident_updated', {
        incidentId: data.incidentId,
        status: data.status,
        updatedBy: user.username,
        timestamp: Date.now()
      });
      
      socket.to(`role:org_admin`).emit('incident_updated', {
        incidentId: data.incidentId,
        status: data.status,
        updatedBy: user.username,
        timestamp: Date.now()
      });
    });

    socket.on('copilot_message', async (data: { message: string; assistant: string }) => {
      // Forward to copilot service and stream response
      socket.emit('copilot_typing', {
        status: 'processing',
        message: 'AI is processing your request...'
      });
    });

    // Handle disconnection
    socket.on('disconnect', (reason) => {
      console.log(`🔌 User ${user.username} disconnected (${reason})`);
      socket.leave(`org:${user.organization_id}`);
      socket.leave(`role:${user.role}`);
      socket.leave(`user:${user.id}`);
    });

    // Handle connection errors
    socket.on('error', (error: Error) => {
      console.error(`Socket error for ${user.username}:`, error);
    });
  });

  console.log('✅ WebSocket server initialized');
  return io;
}

// ─── Broadcast Functions ───────────────────────────────────────────────────────

/**
 * Broadcast event to all users in an organization
 */
export function broadcastToOrg(orgId: number, event: string, data: any) {
  if (io) {
    io.to(`org:${orgId}`).emit(event, {
      ...data,
      timestamp: Date.now()
    });
  }
}

/**
 * Broadcast event to users with a specific role
 */
export function broadcastToRole(role: string, event: string, data: any) {
  if (io) {
    io.to(`role:${role}`).emit(event, {
      ...data,
      timestamp: Date.now()
    });
  }
}

/**
 * Send event to a specific user
 */
export function broadcastToUser(userId: number, event: string, data: any) {
  if (io) {
    io.to(`user:${userId}`).emit(event, {
      ...data,
      timestamp: Date.now()
    });
  }
}

/**
 * Broadcast anomaly detection to relevant users
 */
export function broadcastAnomaly(anomaly: any) {
  const orgId = anomaly.organization_id;
  
  // Broadcast to all users in organization
  broadcastToOrg(orgId, 'anomaly:detected', {
    id: anomaly.id,
    z_score: anomaly.z_score,
    severity: anomaly.severity,
    timestamp: anomaly.timestamp,
    detection_method: anomaly.detection_method,
    event_count: anomaly.event_count,
    hybrid_score: anomaly.hybrid_score
  });

  // Send critical alerts to SOC analysts and admins
  if (anomaly.severity === 'CRITICAL' || anomaly.severity === 'HIGH') {
    broadcastToRole('soc_analyst', 'alert:critical', {
      anomaly_id: anomaly.id,
      severity: anomaly.severity,
      z_score: anomaly.z_score,
      title: `🚨 ${anomaly.severity} Severity Anomaly Detected`,
      message: `Z-Score: ${anomaly.z_score.toFixed(2)} | Events: ${anomaly.event_count}/s`
    });

    broadcastToRole('org_admin', 'alert:critical', {
      anomaly_id: anomaly.id,
      severity: anomaly.severity,
      z_score: anomaly.z_score,
      title: `🚨 ${anomaly.severity} Severity Anomaly Detected`,
      message: `Z-Score: ${anomaly.z_score.toFixed(2)} | Events: ${anomaly.event_count}/s`
    });
  }
}

/**
 * Broadcast incident creation
 */
export function broadcastIncident(incident: any) {
  const orgId = incident.organization_id;
  
  broadcastToOrg(orgId, 'incident:created', {
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
    status: incident.status,
    detection_time: incident.detection_time,
    anomaly_id: incident.anomaly_id
  });

  // Notify SOC analysts
  broadcastToRole('soc_analyst', 'incident:assigned', {
    incident_id: incident.id,
    title: incident.title,
    severity: incident.severity,
    message: 'New incident requires investigation'
  });
}

/**
 * Broadcast system health updates
 */
export function broadcastHealthUpdate(health: any) {
  broadcastToRole('org_admin', 'system:health', health);
  broadcastToRole('super_admin', 'system:health', health);
}

/**
 * Broadcast queue statistics
 */
export function broadcastQueueStats(stats: any) {
  broadcastToRole('org_admin', 'system:queue_stats', stats);
}

/**
 * Send notification to specific user
 */
export function sendNotification(userId: number, notification: {
  type: string;
  title: string;
  message: string;
  data?: any;
}) {
  broadcastToUser(userId, 'notification', {
    id: Date.now(),
    ...notification,
    read: false,
    created_at: new Date().toISOString()
  });
}

/**
 * Get connected users count by organization
 */
export function getConnectedUsersCount(orgId?: number) {
  if (!io) return 0;
  
  if (orgId) {
    const room = io.sockets.adapter.rooms.get(`org:${orgId}`);
    return room ? room.size : 0;
  }
  
  return io.sockets.sockets.size;
}

/**
 * Graceful shutdown
 */
export function closeWebSocket() {
  if (io) {
    io.close();
    console.log('✅ WebSocket server closed');
  }
}