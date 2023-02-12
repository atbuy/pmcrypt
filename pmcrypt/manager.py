import os
import secrets
from hashlib import sha256
from typing import Optional, Tuple, Union

_ITERATIONS = 100_000


class PasswordManager:
    def generate_salt(self, length: int = 16) -> str:
        """Generate a random salt.

        Args:
            length: The length of the salt.

        Returns:

            str: The salt.
        """

        return secrets.token_hex(length)

    def get_pepper(self, env_name: Optional[str] = None) -> Union[str, None]:
        """Get the pepper from the environment.

        Args:
            env_name: The name of the environment variable.

        Returns:
            (str, None): The pepper or None if the environment variable is not set.
        """

        env_name = env_name or "PEPPER"
        return os.environ.get(env_name)

    def hash(
        self,
        password: str,
        salt: Optional[str] = None,
        iterations: Optional[int] = None,
    ) -> Tuple[str, str]:
        # Generate salt if not given
        if not salt:
            salt = self.generate_salt()

        # Get pepper from environment
        pepper = self.get_pepper()

        # Hash password with salt `iterations` times.
        hashed = password
        hash_times = _ITERATIONS
        if iterations is not None:
            hash_times = iterations
        for _ in range(hash_times):
            # Salt password
            hashed = hashed + salt

            # Add pepper if it exists
            if pepper:
                hashed = hashed + pepper

            # Hash password + salt + pepper
            encoded = hashed.encode()
            hashed = sha256(encoded).hexdigest()

        return hashed, salt

    def check(
        self,
        password: str,
        hashed_password: str,
        salt: str,
        iterations: Optional[int] = None,
    ) -> bool:
        """Check if the password matches the hashed password.

        Args:
            password: The password to check.
            hashed_password: The hashed password.
            salt: The salt used to hash the password.
            iterations:
                The number of iterations used to hash the password.
                Defaults to _ITERATIONS.

        Returns:
            bool: True if the password matches the hashed password, False otherwise.
        """

        hash_times = iterations or _ITERATIONS
        other_pass, _ = self.hash(password, salt, hash_times)
        return other_pass == hashed_password
