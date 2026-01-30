import {
  IsEmail,
  IsString,
  IsBoolean,
  IsOptional,
  IsNumber,
  MinLength,
  Matches,
} from 'class-validator';

export class UpdateUserByAdminDto {
  @IsString()
  @IsOptional()
  firstName?: string;

  @IsString()
  @IsOptional()
  lastName?: string;

  @IsEmail()
  @IsOptional()
  email?: string;

  @IsString()
  @IsOptional()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password?: string;

  @IsBoolean()
  @IsOptional()
  is_active?: boolean;

  @IsBoolean()
  @IsOptional()
  email_verified?: boolean;

  @IsNumber()
  @IsOptional()
  roleId?: number;
}

