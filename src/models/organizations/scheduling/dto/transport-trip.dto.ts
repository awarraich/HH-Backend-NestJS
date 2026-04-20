import {
  IsArray,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';
import {
  CreateScheduledTaskBase,
  UpdateScheduledTaskBase,
  QueryScheduledTaskBase,
} from './scheduled-task-base.dto';

export class TransportTripDetailsDto {
  @IsString()
  @MaxLength(500)
  pickup_address: string;

  @IsString()
  @MaxLength(500)
  dropoff_address: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  trip_type?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  vehicle_type?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  special_needs?: string[];
}

// `details` is inherited from the base as `Record<string, unknown>`.
// `TransportTripDetailsDto` above documents the expected shape.
export class CreateTransportTripDto extends CreateScheduledTaskBase {}

export class UpdateTransportTripDto extends UpdateScheduledTaskBase {}

export class QueryTransportTripDto extends QueryScheduledTaskBase {
  @IsOptional()
  @IsString()
  trip_type?: string;
}
