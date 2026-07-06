import { BullModule } from '@nestjs/bull'
import { Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { MongooseModule } from '@nestjs/mongoose'
import { AccountsModule } from './domain/accounts/accounts.module'
import { AuthModule } from './domain/auth/auth.module'
import { DiscoveryGateway } from './realtime/discovery.gateway'

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        uri: config.get<string>('MONGODB_URI', 'mongodb://mongo:27017/adpct'),
      }),
    }),
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        redis: parseRedisUrl(config.get<string>('REDIS_URL', 'redis://redis:6379/0')),
      }),
    }),
    AuthModule,
    AccountsModule,
  ],
  providers: [DiscoveryGateway],
})
export class AppModule {}

function parseRedisUrl(value: string) {
  const url = new URL(value)
  return {
    host: url.hostname,
    port: Number(url.port || 6379),
    db: Number(url.pathname.replace('/', '') || 0),
    password: url.password || undefined,
  }
}
