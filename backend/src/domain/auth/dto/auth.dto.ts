import { IsString, MinLength } from 'class-validator'

export class LoginDto {
  @IsString()
  @MinLength(3)
  email!: string

  @IsString()
  @MinLength(8)
  password!: string
}

export class RefreshDto {
  @IsString()
  refreshToken!: string
}

export class ChangePasswordDto {
  @IsString()
  currentPassword!: string

  @IsString()
  @MinLength(12)
  newPassword!: string
}
