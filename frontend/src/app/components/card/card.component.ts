import { Component, HostBinding, Input } from '@angular/core';

@Component({
  selector: '[appCard]',
  templateUrl: './card.component.html',
  styleUrls: ['./card.component.css'],
})
export class CardComponent {
  @Input() class: string = '';
  className = 'p-8 border border-black/20 shadow rounded';
  @HostBinding('class')
  get styles() {
    return `${this.class} ${this.className}`;
  }
}
