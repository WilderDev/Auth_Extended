import {
  Component,
  OnInit,
  OnDestroy,
  ElementRef,
  Renderer2,
} from '@angular/core';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css'],
})
export class DashboardComponent implements OnInit, OnDestroy {
  public user$ = this.authService.currentUser;
  private canvas!: HTMLCanvasElement;
  private context!: CanvasRenderingContext2D;
  private stars!: Star[];
  private animationFrameId!: number;

  constructor(
    private elRef: ElementRef,
    private renderer: Renderer2,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.initializeStarryBackground();
  }

  ngOnDestroy(): void {
    if (this.canvas) {
      document.body.removeChild(this.canvas);
      window.removeEventListener('resize', this.resize);
      window.cancelAnimationFrame(this.animationFrameId);
      document.body.style.backgroundColor = 'white';
    }
  }

  private initializeStarryBackground(): void {
    this.canvas = this.renderer.createElement('canvas');
    this.context = this.canvas.getContext('2d')!;
    this.renderer.appendChild(document.body, this.canvas);
    this.renderer.setStyle(document.body, 'backgroundColor', 'black');
    this.canvas.style.position = 'fixed';
    this.canvas.style.top = '0';
    this.canvas.style.left = '0';
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.canvas.style.zIndex = '-1';

    this.resize();
    window.addEventListener('resize', this.resize);
    this.stars = Array.from(
      { length: 300 },
      () => new Star(this.context, this.canvas)
    );
    this.animate();
  }

  private resize = () => {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
  };

  private animate = () => {
    this.animationFrameId = window.requestAnimationFrame(this.animate);
    this.render();
  };

  private render = () => {
    this.context.fillStyle = 'rgba(1, 4, 35, 0.8)';
    this.context.fillRect(0, 0, this.canvas.width, this.canvas.height);
    this.context.strokeStyle = 'rgba(255, 255, 255, 0.24)';
    this.stars.forEach((star) => star.update());
  };
}

class Star {
  private x!: number;
  private y!: number;
  private radius!: number;
  private lineWidth!: number;
  private vel!: { x: number; y: number };
  private context: CanvasRenderingContext2D;
  private canvas: HTMLCanvasElement;

  constructor(context: CanvasRenderingContext2D, canvas: HTMLCanvasElement) {
    this.context = context;
    this.canvas = canvas;
    this.init();
  }

  init() {
    this.radius = Math.random();
    this.x = this.canvas.width / 2;
    this.y = this.canvas.height / 2;
    this.lineWidth = 0;
    this.vel = {
      x: (Math.random() * 2 - 1) * 0.7,
      y: (Math.random() * 2 - 1) * 0.7,
    };
  }

  update() {
    this.vel.x *= 1.03;
    this.vel.y *= 1.03;
    this.lineWidth += 0.035;
    const x0 = this.x;
    const y0 = this.y;
    this.x += this.vel.x;
    this.y += this.vel.y;
    this.draw(x0, y0);
    if (
      this.x < 0 ||
      this.x > this.canvas.width ||
      this.y < 0 ||
      this.y > this.canvas.height
    ) {
      this.init();
    }
  }

  draw(x0: number, y0: number) {
    this.context.beginPath();
    this.context.moveTo(x0, y0);
    this.context.lineTo(this.x, this.y);
    this.context.lineWidth = this.lineWidth;
    this.context.stroke();
  }
}
