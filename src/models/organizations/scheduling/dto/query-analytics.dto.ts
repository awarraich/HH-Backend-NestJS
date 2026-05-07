import {
  IsOptional,
  IsString,
  IsUUID,
  IsIn,
  Matches,
} from 'class-validator';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const TREND_BUCKETS = ['day', 'week', 'month'] as const;
const UTILIZATION_RESOURCES = ['bed', 'chair'] as const;

export class QueryAnalyticsDto {
  @IsOptional()
  @IsString()
  @Matches(ISO_DATE, { message: 'from must be YYYY-MM-DD' })
  from?: string;

  @IsOptional()
  @IsString()
  @Matches(ISO_DATE, { message: 'to must be YYYY-MM-DD' })
  to?: string;

  @IsOptional()
  @IsUUID('4')
  department_id?: string;

  @IsOptional()
  @IsUUID('4')
  station_id?: string;

  @IsOptional()
  @IsString()
  role?: string;

  @IsOptional()
  @IsString()
  shift_type?: string;
}

export class QueryUtilizationDto extends QueryAnalyticsDto {
  @IsOptional()
  @IsString()
  @IsIn(UTILIZATION_RESOURCES)
  resource?: 'bed' | 'chair';
}

export class QueryHoursTrendDto extends QueryAnalyticsDto {
  @IsOptional()
  @IsString()
  @IsIn(TREND_BUCKETS)
  bucket?: 'day' | 'week' | 'month';
}

export class QueryDayDetailDto {
  @IsString()
  @Matches(ISO_DATE, { message: 'date must be YYYY-MM-DD' })
  date!: string;

  @IsOptional()
  @IsUUID('4')
  department_id?: string;

  @IsOptional()
  @IsUUID('4')
  station_id?: string;
}

const RESOURCE_TYPES = ['shift', 'station', 'room', 'bed', 'chair'] as const;
export type AnalyticsResourceType = (typeof RESOURCE_TYPES)[number];

/**
 * Filters for the resource-browse endpoints. Reuses the analytics range +
 * dimension filters so the browse list is read against the same row universe
 * as the KPIs and graphs above it.
 */
export class QueryResourceBrowseDto extends QueryAnalyticsDto {
  @IsOptional()
  @IsUUID('4')
  room_id?: string;

  @IsOptional()
  @IsUUID('4')
  bed_id?: string;

  @IsOptional()
  @IsUUID('4')
  chair_id?: string;
}

/**
 * Returns the assignments tied to a single resource (shift / station / room /
 * bed / chair) within the analytics range. Used by the inline "view
 * assignments" panel when a user clicks a row in the ResourcesExplorer.
 */
export class QueryResourceAssignmentsDto extends QueryAnalyticsDto {
  @IsString()
  @IsIn(RESOURCE_TYPES)
  resource_type!: AnalyticsResourceType;

  @IsUUID('4')
  resource_id!: string;
}

/**
 * Single-shot department drill-down. Returns the whole hierarchy
 * (stations → rooms → beds/chairs) plus shift and employee aggregates so
 * the comprehensive department modal can render without N+1 round-trips.
 */
export class QueryDepartmentOverviewDto extends QueryAnalyticsDto {
  // Narrows the optional `department_id` from the base class to required.
  @IsUUID('4')
  declare department_id: string;
}
