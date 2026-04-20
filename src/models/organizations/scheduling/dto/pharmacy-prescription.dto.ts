import {
  IsInt,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  CreateScheduledTaskBase,
  UpdateScheduledTaskBase,
  QueryScheduledTaskBase,
} from './scheduled-task-base.dto';

export class PharmacyPrescriptionDetailsDto {
  @IsString()
  @MaxLength(255)
  medication: string;

  @IsOptional()
  @IsString()
  @MaxLength(128)
  dosage?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  quantity?: number;

  @IsOptional()
  @IsString()
  @MaxLength(255)
  prescribed_by?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  allergies?: string;

  @IsOptional()
  @IsString()
  instructions?: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  priority_level?: string;
}

// `details` is inherited from the base as `Record<string, unknown>`.
// `PharmacyPrescriptionDetailsDto` above documents the expected shape.
export class CreatePharmacyPrescriptionDto extends CreateScheduledTaskBase {}

export class UpdatePharmacyPrescriptionDto extends UpdateScheduledTaskBase {}

export class QueryPharmacyPrescriptionDto extends QueryScheduledTaskBase {
  @IsOptional()
  @IsString()
  priority_level?: string;
}
