import { IsNotEmpty, IsString, IsUUID, MaxLength } from 'class-validator';

export class CreateAddressDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  street: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  city: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  state: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(20)
  zipCode: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  country: string;

  @IsUUID()
  @IsNotEmpty()
  userId: string;
}
