import { CommonModule } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  Input,
  NgModule,
  OnChanges,
  SimpleChanges,
} from '@angular/core';
import capitalize from 'lodash-es/capitalize';
import { MaterialModule } from '../../material';
import { ActivityInstanceFormParameter } from '../../types';
import { ActivityInstanceFormParameterBaseModule } from './activity-instance-form-parameter-base.component';
import { ActivityInstanceFormParameterNameModule } from './activity-instance-form-parameter-name.component';
import { ActivityInstanceFormParameterRecModule } from './activity-instance-form-parameter-rec.component';
import { activityInstanceFormParameterStyles } from './shared-styles';

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'parameter-rec-struct',
  styles: [
    activityInstanceFormParameterStyles,
    `
      :host {
        display: block;
        padding-left: 0px;
        width: 100%;
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

      .struct {
        cursor: pointer;
        display: flex;
        padding-right: 40px;
        width: 100%;
      }

      .struct-left {
        align-items: center;
        display: flex;
        flex-grow: 1;
      }
    `,
  ],
  template: `
    <div class="struct">
      <div class="struct-left" (click)="toggleExpanded()">
        <mat-icon *ngIf="expanded">expand_more</mat-icon>
        <mat-icon *ngIf="!expanded">chevron_right</mat-icon>
        <parameter-name [parameter]="parameter"></parameter-name>
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
            subParameter.schema.type === 'series' ||
            subParameter.schema.type === 'struct'
          "
          [parameter]="subParameter"
        ></parameter-rec>
      </li>
    </ul>
  `,
})
export class ActivityInstanceFormParameterRecStructComponent
  implements OnChanges {
  @Input()
  parameter: ActivityInstanceFormParameter | undefined;

  expanded = false;
  subParameters: ActivityInstanceFormParameter[];

  ngOnChanges(changes: SimpleChanges) {
    if (changes.parameter) {
      this.updateSubParameters();
    }
  }

  toggleExpanded() {
    this.expanded = !this.expanded;
  }

  trackBySubParameters(_: number, parameter: ActivityInstanceFormParameter) {
    return parameter.name;
  }

  updateSubParameters() {
    this.subParameters = [];
    const { items: keys } = this.parameter.schema;
    const structKeys = Object.keys(keys).sort();
    for (const key of structKeys) {
      const subParameter: ActivityInstanceFormParameter = {
        error: null,
        loading: false,
        name: capitalize(key),
        schema: this.parameter.schema.items[key],
        value: null,
      };
      this.subParameters.push(subParameter);
    }
  }
}

@NgModule({
  declarations: [ActivityInstanceFormParameterRecStructComponent],
  exports: [ActivityInstanceFormParameterRecStructComponent],
  imports: [
    CommonModule,
    MaterialModule,
    ActivityInstanceFormParameterBaseModule,
    ActivityInstanceFormParameterNameModule,
    ActivityInstanceFormParameterRecModule,
  ],
})
export class ActivityInstanceFormParameterRecStructModule {}