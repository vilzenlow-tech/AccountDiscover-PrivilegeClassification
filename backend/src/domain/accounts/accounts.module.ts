import { Module } from '@nestjs/common'
import { MongooseModule } from '@nestjs/mongoose'
import { AuthModule } from '../auth/auth.module'
import { Account, AccountSchema } from './account.schema'
import { AccountsController, AssetsController, ScansController } from './accounts.controller'
import { AccountsService } from './accounts.service'

@Module({
  imports: [AuthModule, MongooseModule.forFeature([{ name: Account.name, schema: AccountSchema }])],
  controllers: [AccountsController, AssetsController, ScansController],
  providers: [AccountsService],
})
export class AccountsModule {}
