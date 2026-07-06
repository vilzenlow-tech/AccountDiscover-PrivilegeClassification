import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common'
import { AuthGuard } from './auth.guard'
import { AuthService } from './auth.service'
import { ChangePasswordDto, LoginDto, RefreshDto } from './dto/auth.dto'

type AuthedRequest = { user: { sub: string } }

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Post('login')
  login(@Body() payload: LoginDto) {
    return this.auth.login(payload.email, payload.password)
  }

  @Post('refresh')
  refresh(@Body() payload: RefreshDto) {
    return this.auth.refresh(payload.refreshToken)
  }

  @UseGuards(AuthGuard)
  @Post('change-password')
  changePassword(@Req() request: AuthedRequest, @Body() payload: ChangePasswordDto) {
    return this.auth.changePassword(request.user.sub, payload.currentPassword, payload.newPassword)
  }

  @UseGuards(AuthGuard)
  @Get('me')
  me(@Req() request: AuthedRequest) {
    return this.auth.me(request.user.sub)
  }
}
