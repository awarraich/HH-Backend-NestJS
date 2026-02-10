import { IsString, IsNotEmpty, IsOptional, IsUUID } from 'class-validator';

export class CreateReferralMessageDto {
  @IsString()
  @IsNotEmpty()
  message: string;

  @IsOptional()
  @IsUUID()
  receiver_organization_id?: string;
}
