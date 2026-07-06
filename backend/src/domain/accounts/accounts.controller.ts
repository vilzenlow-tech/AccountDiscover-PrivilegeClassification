import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common'
import { AuthGuard } from '../auth/auth.guard'
import { AccountsService } from './accounts.service'
import { CreateAccountDto } from './dto/create-account.dto'

@Controller('accounts')
@UseGuards(AuthGuard)
export class AccountsController {
  constructor(private readonly accounts: AccountsService) {}

  @Get()
  list(@Query('limit') limit?: string) {
    return this.accounts.list(Number(limit) || 200)
  }

  @Get('stats')
  stats() {
    return this.accounts.stats()
  }

  @Post()
  create(@Body() payload: CreateAccountDto) {
    return this.accounts.create(payload)
  }
}

@Controller('assets')
@UseGuards(AuthGuard)
export class AssetsController {
  constructor(private readonly accounts: AccountsService) {}

  @Get()
  list(@Query('limit') limit?: string) {
    return this.accounts.assets(Number(limit) || 200)
  }
}

@Controller('scans')
@UseGuards(AuthGuard)
export class ScansController {
  constructor(private readonly accounts: AccountsService) {}

  @Get()
  list(@Query('limit') limit?: string) {
    return this.accounts.listScans(Number(limit) || 50)
  }

  @Post()
  launch() {
    return this.accounts.launchFullScan()
  }
}
