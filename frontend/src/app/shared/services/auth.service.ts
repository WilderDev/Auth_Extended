import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { BehaviorSubject, take, tap } from 'rxjs';

export const API_URL = 'http://localhost:5000/api/v1';

interface CreateUser {
  name: string;
  email: string;
  password: string;
}

interface User {
  userId: string;
  name: string;
  role: 'admin' | 'user';
}

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private user$ = new BehaviorSubject<User | null>(null);

  constructor(private router: Router, private httpClient: HttpClient) {}

  get currentUser() {
    return this.user$;
  }

  logout() {
    this.httpClient
      .delete<{ msg: string }>(API_URL + '/auth/logout', {
        withCredentials: true,
      })
      .pipe(take(1))
      .subscribe({
        next: () => {
          this.user$.next(null);
          this.router.navigate(['/']);
        },
        error: () => {
          this.user$.next(null);
          this.router.navigate(['/']);
        },
      });
  }

  login(email: string, password: string) {
    return this.httpClient.post<{ user: User }>(
      API_URL + '/auth/login',
      {
        email,
        password,
      },
      { withCredentials: true }
    );
  }

  register(user: CreateUser) {
    return this.httpClient.post<{ msg: string }>(
      API_URL + '/auth/register',
      user
    );
  }

  verifyEmail(email: string, token: string) {
    return this.httpClient.post<{ msg: string }>(API_URL + '/auth/verify', {
      email,
      verificationToken: token,
    });
  }

  setCurrentUser(user: User) {
    this.currentUser.next(user);
    this.router.navigate(['/', 'dashboard']);
  }

  me() {
    return this.httpClient.get<{ user: User }>(API_URL + '/auth/me');
  }

  fogotPassword(email: string) {
    return this.httpClient.post<{ msg: string }>(
      API_URL + '/auth/forgot-password',
      { email }
    );
  }

  resetPassword({
    password,
    email,
    token,
  }: {
    password: string;
    email: string;
    token: string;
  }) {
    return this.httpClient.post<{ msg: string }>(
      API_URL + '/auth/reset-password',
      { password: password, email: email, token: token }
    );
  }
}
