import { Component } from '@angular/core';
import { FormBuilder, FormControl, Validators } from '@angular/forms';
import { Subscription } from 'rxjs';
import { AuthService } from 'src/app/shared/services/auth.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css'],
})
export class RegisterComponent {
  public err: string | null = null;
  public successMessage: string | null = null;
  public loading: boolean = false;

  private authSubscription = new Subscription();

  public registerForm = this.formBuilder.group({
    name: new FormControl<string | null>('', [Validators.required]),
    email: new FormControl<string | null>('', [
      Validators.required,
      Validators.email,
    ]),
    password: new FormControl<string | null>('', [Validators.required]),
  });

  constructor(
    private formBuilder: FormBuilder,
    private authService: AuthService
  ) {}

  submit() {
    if (this.registerForm.invalid) return;
    this.loading = true;
    const formValue = this.registerForm.getRawValue();

    this.authSubscription.add(
      this.authService
        .register({
          name: formValue.name!,
          email: formValue.email!,
          password: formValue.password!,
        })
        .subscribe({
          next: (data) => {
            this.successMessage = data.msg;
            this.loading = false;
          },
          error: (error) => {
            this.err = error.error.msg;
            this.loading = false;
          },
        })
    );
  }

  ngOnDestroy() {
    this.authSubscription.unsubscribe();
  }
}
