import { Component } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { Subscription } from 'rxjs';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
})
export class LoginComponent {
  public err: string | null = null;
  public successMessage: string | null = null;
  public loading = false;

  private authSubscription = new Subscription();

  public loginForm = this.formBuilder.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required],
  });

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService
  ) {}

  submit() {
    if (this.loginForm.invalid) return;

    this.loading = true;
    const { email, password } = this.loginForm.value;

    this.authSubscription.add(
      this.authService.login(email!, password!).subscribe({
        next: (data) => {
          this.authService.setCurrentUser(data.user);
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
