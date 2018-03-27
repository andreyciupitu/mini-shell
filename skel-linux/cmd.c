/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * Ciupitu Andrei-Valentin, 332CC
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "cmd.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define READ		0
#define WRITE		1

#define IN		0
#define OUT		1
#define ERR		2

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	int status;
	char *path;

	path = get_word(dir);

	if (path == NULL)
		return true;

	status = chdir(path);

	/*
	 * Return TRUE if no errors
	 */
	free(path);
	return status == 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 *  Wrapper over dup2 with error handling and file closing.
 */
static void safe_dup2(int oldfd, int newfd)
{
	int rc;

	rc = dup2(oldfd, newfd);
	DIE(rc < 0, "redirect error");

	/*
	 * Close old fd
	 */
	rc = close(oldfd);
	DIE(rc < 0, "error closing file");
}

/**
 * Redirect standard file descriptors
 */
 static void do_redirect(simple_command_t *s)
 {
	int mode;
	int fd_in, fd_out, fd_err, rc;
	char *input, *output, *err;

	if (s == NULL)
		return;

	input = NULL;
	output = NULL;
	err = NULL;

	/*
	 * Redirect to STDIN
	 */
	if (s->in != NULL) {
		input = get_word(s->in);

		mode = O_RDONLY;

		fd_in = open(input, mode);
		DIE(fd_in < 0, "cannot open file");

		safe_dup2(fd_in, STDIN_FILENO);
	}

	/*
	 * Redirect to STDOUT
	 */
	if (s->out != NULL) {
		output = get_word(s->out);

		/*
		 * Check write mode
		 */
		mode = O_WRONLY | O_CREAT;
		if (s->io_flags & IO_OUT_APPEND)
			mode |= O_APPEND;
		else
			mode |= O_TRUNC;

		fd_out = open(output, mode, 0644);
		DIE(fd_out < 0, "cannot open file");

		safe_dup2(fd_out, STDOUT_FILENO);
	}

	/*
	 * Redirect to STDERR
	 */
	if (s->err != NULL) {
		err = get_word(s->err);

		/*
		 * Check if output and error are in the same file
		 */
		if (output != NULL && strcmp(output, err) == 0) {
			rc = dup2(STDOUT_FILENO, STDERR_FILENO);
			DIE(rc < 0, "redirect error");
			return;
		}

		/*
		 * Check write mode
		 */
		mode = O_WRONLY | O_CREAT;
		if (s->io_flags & IO_ERR_APPEND)
			mode |= O_APPEND;
		else
			mode |= O_TRUNC;

		fd_err = open(err, mode, 0644);
		DIE(fd_err < 0, "cannot open file");

		safe_dup2(fd_err, STDERR_FILENO);
	}

	if (input != NULL)
		free(input);
	if (output != NULL)
		free(output);
	if (err != NULL)
		free(err);
 }

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int pid;
	int fd_in, fd_out, fd_err;
	int status;
	int argc;
	char *cmd, *tmp, *token;

	/*
	 * Sanity checks
	 */
	status = SHELL_EXIT;
	if (s == NULL)
		return false;

	cmd = get_word(s->verb);

	/*
	 * Exit command
	 */
	if ((strcmp(cmd, "exit") == 0) || (strcmp(cmd, "quit") == 0)) {
		free(cmd);
		return shell_exit();
	}

	/*
	 * cd command
	 */
	if (strcmp(cmd, "cd") == 0) {
		/*
		 * Save current fds
		 */
		fd_in = dup(STDIN_FILENO);
		fd_out = dup(STDOUT_FILENO);
		fd_err = dup(STDERR_FILENO);

		do_redirect(s);
		status = shell_cd(s->params);

		/*
		 * Restore standard fds
		 */
		safe_dup2(fd_in, STDIN_FILENO);
		safe_dup2(fd_out, STDOUT_FILENO);
		safe_dup2(fd_err, STDERR_FILENO);

		/* TODO err handling */
		close(fd_in);
		close(fd_out);
		close(fd_err);

		free(cmd);
		return status;
	}

	/*
	 * Variable assignment, execute the assignment and return
	 * the exit status
	 */
	if (strchr(cmd, '=') != 0) {
		tmp = strdup(cmd);

		/*
		 * Separate into name and value
		 */
		token = strtok(tmp, "=");
		status = setenv(token, strtok(NULL, ""), true);

		free(tmp);
		free(cmd);
		return status == 0;
	}

	/*
	 * Execute the command.
	 */
	pid = fork();
	switch (pid) {
	case -1:
		return SHELL_EXIT;
	case 0:
		/*
		 * Redirect standard fds.
		 */
		do_redirect(s);

		/*
		 * Launch the command
		 */
		execvp(cmd, get_argv(s, &argc));

		/*
		 * Command is invalid if it got here.
		 */
		fprintf(stderr, "Execution failed for '%s'\n", cmd);
		free(cmd);
		exit(-1);
	default:
		break;
	}
	waitpid(pid, &status, 0);

	free(cmd);

	/*
	 * Return TRUE if no errors.
	 */
	return status == 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pid1, pid2;
	int status1, status2;

	pid1 = fork();
	switch (pid1) {
	case -1:
		return SHELL_EXIT;
	case 0:
		status1 = parse_command(cmd1, level, father);
		exit(-1 * status1);
	default:
		break;
	}

	pid2 = fork();
	switch (pid2) {
	case -1:
		return SHELL_EXIT;
	case 0:
		status2 = parse_command(cmd2, level, father);
		exit(-1 * status2);
	default:
		break;
	}

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);
	return status1 == 0 && status2 == 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int fds[2];
	int pid1, pid2;
	int status1, status2;

	/* TODO redirect the output of cmd1 to the input of cmd2 */
	pipe(fds);

	pid1 = fork();
	switch (pid1) {
	case -1:
		return SHELL_EXIT;
	case 0:
		safe_dup2(fds[1], STDOUT_FILENO);
		//close(fds[0]);
		close(fds[0]);
		status1 = parse_command(cmd1, level, father);
		exit(status1 - 1);
	default:
		break;
	}

	pid2 = fork();
	switch (pid2) {
	case -1:
		return SHELL_EXIT;
	case 0:
		safe_dup2(fds[0], STDIN_FILENO);
		close(fds[1]);
		status2 = parse_command(cmd2, level, father);
		exit(status2 - 1);
	default:
		break;
	}

	close(fds[0]);
	close(fds[1]);

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);


	return status2 == 0;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int status = SHELL_EXIT;

	/*
	 * Sanity checks
	 */
	if (c == NULL)
		return false;

	/*
	 * Execute a simple command
	 */
	if (c->op == OP_NONE) {
		return parse_simple(c->scmd, level, father);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/*
		 * Execute 2 commands in order
		 */
		status = parse_command(c->cmd1, level + 1, c);
		status = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		status = do_in_parallel(c->cmd1, c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_NZERO:
		/*
		 * Execute the first command and execute the second only if
		 * the first fails.
		 */
		status = parse_command(c->cmd1, level + 1, c);
		if (!status)
			status = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/*
		 * Execute the first command and execute the second only if
		 * the first succeeds,
		 */
		status = parse_command(c->cmd1, level + 1, c);
		if (status && status != SHELL_EXIT)
			status = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		status = do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return status;
}
