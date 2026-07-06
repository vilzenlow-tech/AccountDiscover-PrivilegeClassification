import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose'
import { HydratedDocument } from 'mongoose'

export type UserDocument = HydratedDocument<User>

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, lowercase: true, trim: true })
  email!: string

  @Prop({ required: true, trim: true })
  fullName!: string

  @Prop({ required: true })
  passwordHash!: string

  @Prop({ type: [String], default: ['operator'] })
  roles!: string[]

  @Prop({ default: true })
  isActive!: boolean

  @Prop({ default: false })
  mustChangePassword!: boolean

  @Prop()
  refreshTokenHash?: string
}

export const UserSchema = SchemaFactory.createForClass(User)
UserSchema.index({ email: 1 }, { unique: true })
