import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common'
import { AuthService } from './auth.service'

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest<{ headers: { authorization?: string }; user?: unknown }>()
    const [scheme, token] = request.headers.authorization?.split(' ') ?? []
    if (scheme !== 'Bearer' || !token) throw new UnauthorizedException('Missing bearer token')
    request.user = this.auth.verifyAccessToken(token)
    return true
  }
}
