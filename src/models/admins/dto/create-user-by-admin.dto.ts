import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  Matches,
  IsNumber,
  IsOptional,
  MaxLength,
  Validate,
  ValidationArguments,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

@ValidatorConstraint({ name: 'matchPassword', async: false })
export class MatchPasswordConstraint implements ValidatorConstraintInterface {
  validate(confirmPassword: string, args: ValidationArguments): boolean {
    const [relatedPropertyName] = args.constraints as [string];
    const obj = args.object as Record<string, unknown>;
    const relatedValue = obj[relatedPropertyName];
    return confirmPassword === relatedValue;
  }

  defaultMessage(_args: ValidationArguments): string {
    return 'Passwords do not match';
  }
}

export class CreateUserByAdminDto {
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  /** Display name for blog byline (e.g. "Dr. Jane Smith"). Shown as author on blog posts. */
  @IsOptional()
  @IsString()
  @MaxLength(255)
  displayName?: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message:
      'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password: string;

  @IsString()
  @IsNotEmpty()
  @Validate(MatchPasswordConstraint, ['password'])
  confirmPassword: string;

  @IsNumber()
  @IsNotEmpty()
  roleId: number;
}
