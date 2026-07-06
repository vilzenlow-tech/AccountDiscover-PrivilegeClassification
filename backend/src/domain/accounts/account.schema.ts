import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose'
import { HydratedDocument } from 'mongoose'

export type AccountDocument = HydratedDocument<Account>

@Schema({ timestamps: true })
export class Account {
  @Prop({ trim: true })
  username?: string

  @Prop({ trim: true })
  asset?: string

  @Prop({ enum: ['low', 'standard', 'privileged', 'critical'] })
  privilege?: 'low' | 'standard' | 'privileged' | 'critical'

  @Prop({ default: 'scan' })
  source?: string

  @Prop({ default: false })
  pamManaged?: boolean

  @Prop({ type: [String], default: [] })
  evidence?: string[]

  @Prop({ required: true, trim: true })
  asset_id!: string

  @Prop({ required: true, trim: true })
  asset_hostname!: string

  @Prop({ type: String, default: null })
  asset_ip_address!: string | null

  @Prop({ required: true, trim: true })
  platform!: string

  @Prop({ required: true, trim: true })
  source_type!: string

  @Prop({ required: true, trim: true })
  account_name!: string

  @Prop({ required: true, trim: true })
  principal_type!: string

  @Prop({ required: true, trim: true })
  auth_source!: string

  @Prop({ required: true, trim: true })
  enabled_status!: string

  @Prop({ required: true, trim: true })
  interactive_status!: string

  @Prop({ type: Date, default: null })
  last_login!: Date | null

  @Prop({ type: String, default: null })
  last_login_source!: string | null

  @Prop({ required: true, trim: true })
  privilege_classification!: string

  @Prop({ default: 0 })
  privilege_confidence!: number

  @Prop({ default: 0 })
  risk_score!: number

  @Prop({ default: false })
  is_shared!: boolean

  @Prop({ default: false })
  password_never_expires!: boolean

  @Prop({ type: String, default: null })
  owner!: string | null

  @Prop({ type: Object, default: null })
  evidence_summary!: Record<string, unknown> | null

  @Prop({ required: true, trim: true })
  activity_status!: string

  @Prop({ type: Boolean, default: null })
  never_logged_in!: boolean | null

  @Prop({ type: [String], default: [] })
  account_groups!: string[]

  @Prop({ type: String, default: null })
  remark!: string | null

  @Prop({ default: false })
  locked!: boolean
}

export const AccountSchema = SchemaFactory.createForClass(Account)
AccountSchema.index({ account_name: 1, asset_id: 1, platform: 1 }, { unique: true })
