import { Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { InjectModel } from '@nestjs/mongoose'
import { createHmac, pbkdf2Sync, randomBytes, timingSafeEqual } from 'crypto'
import { Model } from 'mongoose'
import { User, UserDocument } from './user.schema'

type TokenPayload = {
  sub: string
  email: string
  roles: string[]
  type: 'access' | 'refresh'
  exp: number
}

@Injectable()
export class AuthService implements OnModuleInit {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
    private readonly config: ConfigService,
  ) {}

  async onModuleInit() {
    const email = this.config.get<string>('ADMIN_EMAIL', 'admin@local').toLowerCase()
    const existing = await this.userModel.exists({ email })
    if (!existing) {
      await this.userModel.create({
        email,
        fullName: 'Platform Administrator',
        passwordHash: this.hashPassword(this.config.get<string>('ADMIN_PASSWORD', 'ChangeMe!123')),
        roles: ['admin', 'operator'],
        isActive: true,
        mustChangePassword: true,
      })
    }
  }

  async login(email: string, password: string) {
    const user = await this.userModel.findOne({ email: email.toLowerCase(), isActive: true }).exec()
    if (!user || !this.verifyPassword(password, user.passwordHash)) {
      throw new UnauthorizedException('Invalid email or password')
    }
    return this.issueTokens(user)
  }

  async refresh(refreshToken: string) {
    const payload = this.verifyToken(refreshToken, 'refresh')
    const user = await this.userModel.findById(payload.sub).exec()
    if (!user?.isActive || !user.refreshTokenHash || !this.verifyDigest(refreshToken, user.refreshTokenHash)) {
      throw new UnauthorizedException('Invalid refresh token')
    }
    return this.issueTokens(user)
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const user = await this.userModel.findById(userId).exec()
    if (!user?.isActive || !this.verifyPassword(currentPassword, user.passwordHash)) {
      throw new UnauthorizedException('Invalid current password')
    }
    user.passwordHash = this.hashPassword(newPassword)
    user.mustChangePassword = false
    await user.save()
    return this.issueTokens(user)
  }

  async me(userId: string) {
    const user = await this.userModel.findById(userId).lean().exec()
    if (!user?.isActive) throw new UnauthorizedException('Invalid user')
    return this.toProfile(user)
  }

  verifyAccessToken(token: string) {
    return this.verifyToken(token, 'access')
  }

  private async issueTokens(user: UserDocument) {
    const profile = this.toProfile(user)
    const accessToken = this.signToken({
      sub: user.id,
      email: user.email,
      roles: user.roles,
      type: 'access',
      exp: Math.floor(Date.now() / 1000) + 15 * 60,
    })
    const refreshToken = this.signToken({
      sub: user.id,
      email: user.email,
      roles: user.roles,
      type: 'refresh',
      exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    })
    user.refreshTokenHash = this.digest(refreshToken)
    await user.save()
    return { accessToken, refreshToken, expiresIn: 900, user: profile }
  }

  private toProfile(user: User | UserDocument) {
    return {
      id: String('_id' in user ? user._id : ''),
      email: user.email,
      fullName: user.fullName,
      roles: user.roles,
      isActive: user.isActive,
      mustChangePassword: user.mustChangePassword,
    }
  }

  private hashPassword(password: string) {
    const salt = randomBytes(16).toString('hex')
    const hash = pbkdf2Sync(password, salt, 120000, 32, 'sha256').toString('hex')
    return `${salt}:${hash}`
  }

  private verifyPassword(password: string, stored: string) {
    const [salt, expected] = stored.split(':')
    const actual = pbkdf2Sync(password, salt, 120000, 32, 'sha256')
    return this.safeEqual(actual, Buffer.from(expected, 'hex'))
  }

  private signToken(payload: TokenPayload) {
    const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
    const signature = createHmac('sha256', this.secret()).update(body).digest('base64url')
    return `${body}.${signature}`
  }

  private verifyToken(token: string, type: TokenPayload['type']) {
    const [body, signature] = token.split('.')
    if (!body || !signature) throw new UnauthorizedException('Invalid token')
    const expected = createHmac('sha256', this.secret()).update(body).digest('base64url')
    if (!this.safeEqual(Buffer.from(signature), Buffer.from(expected))) {
      throw new UnauthorizedException('Invalid token')
    }
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as TokenPayload
    if (payload.type !== type || payload.exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedException('Expired token')
    }
    return payload
  }

  private digest(value: string) {
    return createHmac('sha256', this.secret()).update(value).digest('hex')
  }

  private verifyDigest(value: string, expected: string) {
    return this.safeEqual(Buffer.from(this.digest(value)), Buffer.from(expected))
  }

  private safeEqual(actual: Buffer, expected: Buffer) {
    return actual.length === expected.length && timingSafeEqual(actual, expected)
  }

  private secret() {
    return this.config.get<string>('AUTH_SECRET', 'dev-only-change-this-auth-secret')
  }
}
