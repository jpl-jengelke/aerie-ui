import { CommonModule } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  Input,
  NgModule,
  OnChanges,
  SimpleChanges,
} from '@angular/core';
import { MaterialModule } from '../../material';
import { ActivityInstanceFormParameter } from '../../types';
import { ActivityInstanceFormParameterBaseModule } from './activity-instance-form-parameter-base.component';
import { ActivityInstanceFormParameterNameModule } from './activity-instance-form-parameter-name.component';
import { ActivityInstanceFormParameterRecModule } from './activity-instance-form-parameter-rec.component';
import { activityInstanceFormParameterStyles } from './shared-styles';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'parameter-rec-series',
  styles: [
    activityInstanceFormParameterStyles,
    `
      :host {
        display: block;
        padding-left: 0px;
        width: 100%;
      }

      mat-form-field {
        width: 50px;
      }

      mat-icon {
        color: rgba(0, 0, 0, 0.6);
      }

      ul {
        margin: 0;
        padding-inline-start: 20px;
      }

      li {
        list-style: none;
      }

      .series {
        cursor: pointer;
        display: flex;
        padding-right: 40px;
        width: 100%;
      }

      .series-left {
        align-items: center;
        display: flex;
        flex-grow: 1;
      }

      .series-right {
        align-items: center;
        justify-content: flex-end;
        padding-right: 10px;
      }
    `,
  ],
  template: `
    <div class="series">
      <div class="series-left" (click)="toggleExpanded()">
        <mat-icon *ngIf="expanded">expand_more</mat-icon>
        <mat-icon *ngIf="!expanded">chevron_right</mat-icon>
        <parameter-name [parameter]="parameter"></parameter-name>
      </div>
      <div class="series-right">
        <mat-form-field floatLabel="always">
          <mat-label>Indices</mat-label>
          <input
            matInput
            type="number"
            [value]="indices"
            (change)="onIndicesChange($event)"
          />
        </mat-form-field>
      </div>
    </div>

    <ul *ngIf="expanded">
      <li
        *ngFor="
          let subParameter of subParameters;
          trackBy: trackBySubParameters
        "
      >
        <parameter-base
          *ngIf="
            subParameter.schema.type !== 'series' &&
            subParameter.schema.type !== 'struct'
          "
          [parameter]="subParameter"
        ></parameter-base>

        <parameter-rec
          *ngIf="
            parameter.schema.type === 'series' ||
            parameter.schema.type === 'struct'
          "
          [parameter]="subParameter"
        ></parameter-rec>
      </li>
    </ul>
  `,
})
export class ActivityInstanceFormParameterRecSeriesComponent
  implements OnChanges {
  @Input()
  parameter: ActivityInstanceFormParameter | undefined;

  expanded = false;
  indices = 1;
  subParameters: ActivityInstanceFormParameter[] = [];

  ngOnChanges(changes: SimpleChanges) {
    if (changes.parameter) {
      this.updateSubParameters();
    }
  }

  onIndicesChange(event: Event) {
    const { valueAsNumber } = event.target as HTMLInputElement;
    this.indices = valueAsNumber;
    this.updateSubParameters();
  }

  toggleExpanded() {
    this.expanded = !this.expanded;
  }

  trackBySubParameters(_: number, parameter: ActivityInstanceFormParameter) {
    return parameter.name;
  }

  updateSubParameters() {
    this.subParameters = [];
    for (let i = 0; i < this.indices; ++i) {
      const subParameter: ActivityInstanceFormParameter = {
        error: null,
        loading: false,
        name: `Index ${i + 1}`,
        schema: this.parameter.schema.items,
        value: null,
      };
      this.subParameters.push(subParameter);
    }
  }
}

@NgModule({
  declarations: [ActivityInstanceFormParameterRecSeriesComponent],
  exports: [ActivityInstanceFormParameterRecSeriesComponent],
  imports: [
    CommonModule,
    MaterialModule,
    ActivityInstanceFormParameterBaseModule,
    ActivityInstanceFormParameterNameModule,
    ActivityInstanceFormParameterRecModule,
  ],
})
export class ActivityInstanceFormParameterRecSeriesModule {}