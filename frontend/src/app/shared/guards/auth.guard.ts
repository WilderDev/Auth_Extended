import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { inject } from '@angular/core';

export const authGuard: CanActivateFn = (route, state) => {
  return inject(AuthService).currentUser.value
    ? true
    : inject(Router).createUrlTree(['/', 'login']);
};

export const loginGuard: CanActivateFn = (route, state) => {
  return inject(AuthService).currentUser.value
    ? inject(Router).createUrlTree(['/', 'dashboard'])
    : true;
};
