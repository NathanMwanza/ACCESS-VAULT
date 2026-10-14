import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import App from '../src/App.jsx';
import { AuthProvider } from '../src/context/AuthContext.jsx';
import { __resetMockAuth, __setMockLatency, DEMO_USER } from '../src/services/mock/mockAuthApi.js';

function renderApp(route = '/login') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  __resetMockAuth();
  __setMockLatency(0);
});

describe('Login screen', () => {
  it('shows field errors and does not submit empty input', async () => {
    const user = userEvent.setup();
    renderApp();
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByText(/Enter your email/)).toBeInTheDocument();
    expect(screen.getByText(/Enter your password/)).toBeInTheDocument();
  });

  it('signs in with the demo account and reaches the vault', async () => {
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText('Email'), DEMO_USER.email);
    await user.type(screen.getByLabelText('Password'), DEMO_USER.password);
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByText(/Your vault is locked and empty/)).toBeInTheDocument();
  });

  it('shows one generic error for a wrong password', async () => {
    const user = userEvent.setup();
    renderApp();
    await user.type(screen.getByLabelText('Email'), DEMO_USER.email);
    await user.type(screen.getByLabelText('Password'), 'not the password');
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect email or password.');
  });

  it('protects /vault when signed out', () => {
    renderApp('/vault');
    expect(screen.getByRole('heading', { name: /welcome back/i })).toBeInTheDocument();
  });
});

describe('Register screen', () => {
  it('blocks mismatched passwords', async () => {
    const user = userEvent.setup();
    renderApp('/register');
    await user.type(screen.getByLabelText('Your name'), 'Dalitso');
    await user.type(screen.getByLabelText('Email'), 'new@user.co');
    await user.type(screen.getByLabelText('Password'), 'a-long-test-password');
    await user.type(screen.getByLabelText('Confirm password'), 'a-different-password');
    await user.click(screen.getByRole('button', { name: /create account/i }));
    expect(await screen.findByText(/do not match/)).toBeInTheDocument();
  });

  it('creates an account, lands in the vault, and can sign out and back in', async () => {
    const user = userEvent.setup();
    renderApp('/register');
    await user.type(screen.getByLabelText('Your name'), 'Dalitso');
    await user.type(screen.getByLabelText('Email'), 'new@user.co');
    await user.type(screen.getByLabelText('Password'), 'a-long-test-password');
    await user.type(screen.getByLabelText('Confirm password'), 'a-long-test-password');
    await user.click(screen.getByRole('button', { name: /create account/i }));
    expect(await screen.findByText(/Your account is ready/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /sign out/i }));
    expect(await screen.findByText(/You have been signed out/)).toBeInTheDocument();

    await user.type(screen.getByLabelText('Email'), 'new@user.co');
    await user.type(screen.getByLabelText('Password'), 'a-long-test-password');
    await user.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(screen.getByText(/Your vault is locked and empty/)).toBeInTheDocument());
  });

  it('shows email_taken on the email field', async () => {
    const user = userEvent.setup();
    renderApp('/register');
    await user.type(screen.getByLabelText('Your name'), 'Someone');
    await user.type(screen.getByLabelText('Email'), DEMO_USER.email);
    await user.type(screen.getByLabelText('Password'), 'a-long-test-password');
    await user.type(screen.getByLabelText('Confirm password'), 'a-long-test-password');
    await user.click(screen.getByRole('button', { name: /create account/i }));
    expect(await screen.findByText(/already exists/)).toBeInTheDocument();
  });
});
