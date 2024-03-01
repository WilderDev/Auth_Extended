import { Component, HostBinding, Input } from '@angular/core';

@Component({
  selector: 'button[appButton]',
  templateUrl: './button.component.html',
  styleUrls: ['./button.component.css'],
})
export class ButtonComponent {
  @Input() class: string = '';
  className =
    'px-4 py-2 border border-black/20 shadow rounded hover:bg-gray-100 transition-colors duration-150 ease-in-out font-semibold';
  @HostBinding('class')
  get styles() {
    return `${this.class} ${this.className}`;
  }
}
