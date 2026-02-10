import { IsString, IsOptional, IsIn, MaxLength } from 'class-validator';

export class UpdateReferralResponseDto {
  @IsString()
  @IsIn(['accepted', 'declined', 'negotiation'])
  response_status: 'accepted' | 'declined' | 'negotiation';

  @IsOptional()
  @IsString()
  proposed_terms?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}
