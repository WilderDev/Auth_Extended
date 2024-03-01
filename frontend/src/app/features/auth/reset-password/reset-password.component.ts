import { Component } from '@angular/core';
import { Validators, FormBuilder } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { Subscription } from 'rxjs';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrl: './reset-password.component.css',
})
export class ResetPasswordComponent {
  public err: string | null = null;
  public successMessage: string | null = null;
  public loading = false;

  private token: string | null = null;
  private email: string | null = null;

  private authSubscription = new Subscription();

  public resetPasswordForm = this.formBuilder.group({
    password: ['', [Validators.required]],
  });

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService,
    private activatedRoute: ActivatedRoute,
    private router: Router
  ) {}

  ngOnInit() {
    this.activatedRoute.queryParams.subscribe((params) => {
      const token = params['token'];
      const email = params['email'];

      if (!token || !email) this.router.navigate(['/']);

      this.token = token;
      this.email = email;
    });
  }

  submit() {
    if (this.resetPasswordForm.invalid || !this.token || !this.email) return;

    this.loading = true;
    const { password } = this.resetPasswordForm.value;

    this.authSubscription.add(
      this.authService
        .resetPassword({
          password: password!,
          email: this.email!,
          token: this.token!,
        })
        .subscribe({
          next: (data) => {
            this.successMessage = data.msg;
            this.loading = false;
            setTimeout(() => {
              this.router.navigate(['/login']);
            }, 2000);
          },
          error: (error) => {
            this.err = error.error?.msg || 'An unexpected error occurred';
            this.loading = false;
          },
        })
    );
  }

  ngOnDestroy() {
    this.authSubscription.unsubscribe();
  }
}
