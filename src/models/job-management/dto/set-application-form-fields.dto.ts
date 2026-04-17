import {
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsIn,
  IsObject,
  IsOptional,
  IsString,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

/**
 * Shape of a single field in the per-organization job-application form.
 * Kept intentionally broad (a couple of dozen valid `type`s exist) but
 * every field must still have a stable `id` + `name` + `label` so the
 * apply page can render inputs and submit a round-trippable answer map.
 */
export class ApplicationFormFieldDto {
  @IsString()
  @MaxLength(128)
  id: string;

  @IsString()
  @MaxLength(128)
  name: string;

  @IsString()
  @MaxLength(256)
  label: string;

  /**
   * Input kind. Not an enum on purpose — new types get added from the UI
   * builder faster than the backend ships. We still cap the length so bogus
   * blobs can't sneak into the JSONB column.
   */
  @IsString()
  @MaxLength(64)
  type: string;

  @IsOptional()
  @IsBoolean()
  required?: boolean;

  @IsOptional()
  @IsString()
  @MaxLength(256)
  placeholder?: string;

  @IsOptional()
  @IsString()
  @MaxLength(2000)
  description?: string;

  /** For dropdown / radio / multi-select — max 200 options per field. */
  @IsOptional()
  @IsArray()
  @ArrayMaxSize(200)
  @IsString({ each: true })
  options?: string[];

  /**
   * Builder-only metadata (group labels, width hints, etc.). Kept as an
   * opaque record so the frontend can evolve without a backend change, but
   * typed as object to reject primitives/arrays.
   */
  @IsOptional()
  @IsObject()
  meta?: Record<string, unknown>;

  @IsOptional()
  @IsString()
  @IsIn(['required', 'optional'])
  group?: 'required' | 'optional';
}

export class SetApplicationFormFieldsDto {
  @IsArray()
  @ArrayMaxSize(200)
  @ValidateNested({ each: true })
  @Type(() => ApplicationFormFieldDto)
  fields: ApplicationFormFieldDto[];
}
