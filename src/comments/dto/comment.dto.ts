import { ApiProperty } from '@nestjs/swagger';

export class CreateCommentDto {
  @ApiProperty() readonly comment: string;
  @ApiProperty() car: string;
}
