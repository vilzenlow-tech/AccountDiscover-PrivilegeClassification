import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets'
import { Server, Socket } from 'socket.io'

@WebSocketGateway({ cors: { origin: process.env.APP_CORS_ORIGINS ?? 'http://localhost:5173' } })
export class DiscoveryGateway {
  @WebSocketServer()
  server!: Server

  @SubscribeMessage('discovery:subscribe')
  subscribe(@ConnectedSocket() client: Socket, @MessageBody() scope: string) {
    void client.join(scope || 'default')
    return { event: 'discovery:subscribed', scope: scope || 'default' }
  }
}
