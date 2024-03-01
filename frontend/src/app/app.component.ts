import { Component } from '@angular/core';
import { AuthService } from './shared/services/auth.service';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent {
  title = 'authentication';
  user$ = this.authService.currentUser;

  private authSubscription = new Subscription();

  constructor(private authService: AuthService) {}

  ngOnInit() {
    this.authSubscription.add(
      this.authService.me().subscribe({
        next: (res) => {
          if (res.user) {
            this.authService.setCurrentUser(res.user);
          }
        },
        error: (err) => {
          console.log('Failed to get user');
        },
      })
    );
  }

  ngOnDestroy() {
    this.authSubscription.unsubscribe();
  }
}
