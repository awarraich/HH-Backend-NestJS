import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

/**
 * DTO for updating the current user's profile (first name, last name).
 * All fields are optional; only provided fields are updated.
 */
export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MinLength(1, { message: 'First name cannot be empty' })
  @MaxLength(255)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MinLength(1, { message: 'Last name cannot be empty' })
  @MaxLength(255)
  lastName?: string;
}
