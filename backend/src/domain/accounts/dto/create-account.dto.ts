import { IsArray, IsBoolean, IsIn, IsOptional, IsString, MinLength } from 'class-validator'

export class CreateAccountDto {
  @IsString()
  @MinLength(1)
  username!: string

  @IsString()
  @MinLength(1)
  asset!: string

  @IsIn(['low', 'standard', 'privileged', 'critical'])
  privilege!: 'low' | 'standard' | 'privileged' | 'critical'

  @IsOptional()
  @IsString()
  source?: string

  @IsOptional()
  @IsBoolean()
  pamManaged?: boolean

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  evidence?: string[]
}
