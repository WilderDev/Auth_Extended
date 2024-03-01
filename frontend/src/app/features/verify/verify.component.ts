import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-verify',
  templateUrl: './verify.component.html',
  styleUrls: ['./verify.component.css'],
})
export class VerifyComponent implements OnInit, OnDestroy {
  public loading = false;
  public err: string | null = null;
  public successMessage: string | null = null;

  private routeSubscription = new Subscription();

  constructor(
    private activatedRoute: ActivatedRoute,
    private authService: AuthService
  ) {}

  // https://frontend.com/verify?token=${lkdjflksjdflkj}&email=${email}

  ngOnInit() {
    this.routeSubscription.add(
      this.activatedRoute.queryParams.subscribe({
        next: ({ token, email }) => {
          if (!token || !email) {
            this.err = 'Failed To Verify Email';
            return;
          }
          this.loading = true;
          this.verifyEmail(email, token);
        },
        error: () => (this.err = 'Failed To Verify Email'),
      })
    );
  }

  private verifyEmail(email: string, token: string) {
    this.authService.verifyEmail(email, token).subscribe({
      next: (data) => {
        this.loading = false;
        this.successMessage = data.msg;
      },
      error: (error) => {
        this.loading = false;
        this.err = error.error?.msg || 'Verification failed';
      },
    });
  }

  ngOnDestroy() {
    this.routeSubscription.unsubscribe();
  }
}
