import { Component } from '@angular/core';
import { Validators, FormBuilder } from '@angular/forms';
import { Subscription } from 'rxjs';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrl: './forgot-password.component.css',
})
export class ForgotPasswordComponent {
  public err: string | null = null;
  public successMessage: string | null = null;
  public loading = false;

  private authSubscription = new Subscription();

  public forgotPasswordForm = this.formBuilder.group({
    email: ['', [Validators.required, Validators.email]],
  });

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService
  ) {}

  submit() {
    if (this.forgotPasswordForm.invalid) return;

    this.loading = true;
    const { email } = this.forgotPasswordForm.value;

    this.authSubscription.add(
      this.authService.fogotPassword(email!).subscribe({
        next: (data) => {
          this.successMessage = data.msg;
          this.loading = false;
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
