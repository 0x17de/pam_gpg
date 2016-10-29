#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

// Strength of the test
#define TO_SIGN_BUFFER_SIZE 1024
// Maximum Message size when signed
#define SIGNED_BUFFER_SIZE 4096

#define GPG_PATH "/usr/bin/gpg"
#define GPG_HEAD "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA1"


static const char* base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890+/";

static size_t genRandomBase64Data(char* buffer) {
	FILE* fUrandom = fopen("/dev/urandom", "rb");
	if (!fUrandom) return 0;
	
	size_t length = 0;

	char tempData[3];
	int i;
	for (i = 0; i < ((TO_SIGN_BUFFER_SIZE - 1) / 4); ++i) {
		fread(tempData, 1, 3, fUrandom);
		*buffer = base64chars[(tempData[0] >> 2)&0x3f]; ++buffer;
		*buffer = base64chars[((tempData[0] << 4) + ((tempData[1] >> 4)&0x3f))&0x3f]; ++buffer;
		*buffer = base64chars[((tempData[1] << 2) + ((tempData[2] >> 6)&0x3f))&0x3f]; ++buffer;
		*buffer = base64chars[tempData[2]&0x3f]; ++buffer;
		length += 4;
	}
	*buffer = 0;

	fclose(fUrandom);
	return length;
}

static size_t readMessage(pid_t pid, char* buffer, size_t canRead, int fd) {
	int status;
	waitpid(pid, &status, 0); // wait for process to end
	if (status != 0)
		return 0;

	size_t dataRead = 0;
	char* bufferPtr = buffer;
	--canRead; // nullbyte
	while (1) {
		if (canRead == 0)
			return 0; // abort, buffer too small

		size_t ret = read(fd, bufferPtr, canRead);
		if (ret == -1 || ret == 0)
			break;
		canRead -= ret;
		bufferPtr += ret;
		dataRead += ret;
		if (ret < canRead)
			break;
	}
	close(fd);
	*bufferPtr = 0;

	return dataRead;
}

static int requestSignature(char* toSignBuffer, unsigned int length, char* signedBuffer, size_t* sigLength) {
	int fdRequestSig1[2];
	if (pipe(fdRequestSig1))
		return 1;
	int fdRequestSig2[2];
	if (pipe(fdRequestSig2)) {
		close(fdRequestSig1[0]);
		close(fdRequestSig1[1]);
		return 2;
	}

	pid_t pid = fork();
	if (pid == -1) {
		return 3;
	} else if (pid == 0) {
		close(fdRequestSig1[1]);
		close(fdRequestSig2[0]);
		dup2(fdRequestSig1[0], STDIN_FILENO);
		dup2(fdRequestSig2[1], STDOUT_FILENO);
		close(fdRequestSig1[0]);
		close(fdRequestSig2[1]);
		close(STDERR_FILENO); // Less printing
		char* const argv[] = {GPG_PATH, "--no-default-keyring", "--keyring", "/etc/authorized_pubkey.gpg", "--armor", "--detach-sign", 0};
		execv(GPG_PATH, argv);
		exit(1);
	} else {
		close(fdRequestSig2[1]);
		close(fdRequestSig1[0]);
		write(fdRequestSig1[1], toSignBuffer, length);
		close(fdRequestSig1[1]);

		*sigLength = readMessage(pid, signedBuffer, SIGNED_BUFFER_SIZE, fdRequestSig2[0]);
		if (*sigLength == 0)
			return 4;

		return 0;
	}
	return 5;
}

static int verifyData(char* toSignBuffer, char* signedBuffer, size_t sigLength) {
	int fdVerifyData1[2];
	if (pipe(fdVerifyData1))
		return 1;

	pid_t pid = fork();
	if (pid == -1) {
		return 2;
	} else if (pid == 0) {
		close(fdVerifyData1[1]);
		dup2(fdVerifyData1[0], STDIN_FILENO);
		close(fdVerifyData1[0]);
		close(STDERR_FILENO); // Less printing
		char* const argv[] = {GPG_PATH, "--no-default-keyring", "--keyring", "/etc/authorized_pubkey.gpg", "--verify", 0};
		execv(GPG_PATH, argv);
		exit(1);
	} else {
		close(fdVerifyData1[0]);

		char buffer[SIGNED_BUFFER_SIZE + 1024];
		int ret = snprintf(buffer, SIGNED_BUFFER_SIZE + 1024, GPG_HEAD "\n\n%s\n%s\n", toSignBuffer, signedBuffer);
		if (ret <= 0) {
			close(fdVerifyData1[1]);
			return 5;
		}

		write(fdVerifyData1[1], buffer, ret);
		close(fdVerifyData1[1]);

		int status;
		waitpid(pid, &status, 0); // wait for process to end
		if (status != 0)
			return 3;

		return 0; // Ok.
	}
	
	return 4;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	char toSignBuffer[TO_SIGN_BUFFER_SIZE];
	int error = PAM_SUCCESS;

	size_t length = genRandomBase64Data(toSignBuffer);
	if (length == 0)
		error = PAM_AUTH_ERR;

	if (error == PAM_SUCCESS) {
		char signedBuffer[SIGNED_BUFFER_SIZE];
		size_t sigLength;
		if (requestSignature(toSignBuffer, length, signedBuffer, &sigLength)) {
			error = PAM_AUTH_ERR;
		} else {
			if (verifyData(toSignBuffer, signedBuffer, sigLength))
				error = PAM_AUTH_ERR;
		}
	}

	return error ? PAM_AUTH_ERR : PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	FILE* fUrandom = fopen("/dev/urandom", "rb");
	if (!fUrandom) return PAM_CRED_ERR;
	fclose(fUrandom);

	return PAM_SUCCESS;
}

#ifdef LIBTEST
int main(int argc, char* argv[]) {
	int ret = pam_sm_authenticate(0, 0, 0, 0);
	printf("%s\n", ret == PAM_SUCCESS ? "OK" : "Failed");
	return 0;
}
#endif
