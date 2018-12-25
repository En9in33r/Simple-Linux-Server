/*
  Простой сервер, создаваемый сугубо в научно-исследовательских целях.

  При подключении запрашиваются логин (login) и пароль (password). Вводимые клиентом и присылаемые на сервер
  данные ищутся в файле паролей Linux, после подтверждения осуществляется вход.

  Во время сеанса возможен ввод команд:
  ls - просмотр каталогов и файлов в текущем каталоге
  cd <path> - переход к каталогу
  rm - удаление файла или каталога
  exit - выход

  Сервер работает непрерывно (это демон).
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <shadow.h>
#include <crypt.h>
#include <pwd.h>
#include <sys/stat.h>
#include <fcntl.h>

struct passwd *pw; // struct for password file
struct spwd *sp;  // struct for shadow password file

struct addrinfo min_info_strc; // addrinfo with minimum of information
struct addrinfo *full_info_strc; // addrinfo which will be filled by getaddrinfo()

char *full_encrypted_pass;

int sck, new_sck; // my and client socket's address

struct sockaddr_storage their_addr; // info about incoming connection will go here

socklen_t addr_size; // address size

// extended getaddrinfo() with memset and error checking
void e_gai(char port_number[5])
{
  int status; // code which will be returned by getaddrinfo()

  memset(&min_info_strc, 0, sizeof min_info_strc); // fill min addrinfo by zeros

  min_info_strc.ai_family = AF_INET; // ipv4 and ipv6
  min_info_strc.ai_socktype = SOCK_STREAM; // tcp
  min_info_strc.ai_flags = AI_PASSIVE; // localhost

  status = getaddrinfo(NULL, port_number, &min_info_strc, &full_info_strc);
  if (status != 0) // 0 is correct
  {
    fprintf(stderr, "e_gai() error: %s\n", gai_strerror(status)); // print error in console
    exit(1);
  }
}

// extended socket() with sck value assignment and error checking
void e_socket(int domain, int type, int protocol)
{
  sck = socket(domain, type, protocol);

  if (sck == -1) // -1 is error
  {
    fprintf(stderr, "e_socket() error: %s\n", gai_strerror(sck));
    exit(1);
  }
}

// extended bind() with error checking
void e_bind(int socket_address, struct sockaddr *my_addr, int addrlen)
{
  if (bind(socket_address, my_addr, addrlen) == -1) // -1 is error
  {
    fprintf(stderr, "e_bind() error: %s\n", gai_strerror(-1));
    exit(1);
  }
}

// extended listen() with error checking
// socket_address is sock file descr
// count_of_connections - maximum allowed connections
void e_listen(int socket_address, int count_of_connections)
{
  if (listen(socket_address, count_of_connections) == -1) // -1 is error
  {
    fprintf(stderr, "e_listen() error: %s\n", gai_strerror(-1));
    exit(1);
  }
}

// extended accept() with addr_size initialization (size of client's address), client socket's creation and error checking
void e_accept(int socket_address)
{
  // interaction with client is here
  while(1)
  {
    full_encrypted_pass = malloc(150);

    addr_size = sizeof their_addr; // initializing their address's size

    new_sck = accept(socket_address, (struct sockaddr *)&their_addr, &addr_size); // my socket's adress, their sockaddr, their address's size

    if (new_sck == -1) // error checking
    {
      fprintf(stderr, "e_accept() error: %s\n", gai_strerror(-1));
      exit(1);
    }

    char recieve_login_buffer[20]; // buffer for recieved login
    char recieve_password_buffer[20]; // buffer for recieved password

    char *sending_msg = malloc(100); // pointer for every message that server sends to client

    freeaddrinfo(full_info_strc); // clear the structure

    sending_msg = "Simple Linux Server 0.1beta\n"; // puts a message to my variable
    send(new_sck, sending_msg, strlen(sending_msg), 0); // send() this message
    memset(&sending_msg, 0, sizeof sending_msg); // clear my favourite variable

    sending_msg = "Please, enter login and password.\n"; // puts a message to my variable
    send(new_sck, sending_msg, strlen(sending_msg), 0); // send() this message
    memset(&sending_msg, 0, sizeof sending_msg); // clear my favourite variable

    int password_and_login_are_correct = 0; // (instead of bool)
    while (password_and_login_are_correct == 0) // checking if entered login and password are not correct
    {
      int login_bytes_recieved, password_bytes_recieved; // variables for counts of recieved bytes

      sending_msg = "Login: "; // same thing
      send(new_sck, sending_msg, strlen(sending_msg), 0);
      memset(&sending_msg, 0, sizeof sending_msg);

      login_bytes_recieved = recv(new_sck, &recieve_login_buffer, sizeof recieve_login_buffer, 0); // recv() the login from client to first buffer
      if (login_bytes_recieved > 2) // if length of login is bigger than 0 (recv() things that recieves 2 bytes more data)
      {
        recieve_login_buffer[login_bytes_recieved - 2] = '\0'; // add the null-terminator to avoid segmentation fault
        printf("Login entered: %s\n", recieve_login_buffer);  // printf() the sended login
        printf("recieved %d bytes\n", login_bytes_recieved);  // and number of bytes
      }
      else
      {
        fprintf(stderr, "recv() error: %s\n", gai_strerror(-1));
        exit(1);
      }

      sending_msg = "Password: "; // same thing [2]
      send(new_sck, sending_msg, strlen(sending_msg), 0);
      memset(&sending_msg, 0, sizeof sending_msg);

      password_bytes_recieved = recv(new_sck, &recieve_password_buffer, sizeof recieve_password_buffer, 0);// recv() the password from client to second buffer
      if (password_bytes_recieved > 2) // if it longer than 0
      {
        recieve_password_buffer[password_bytes_recieved - 2] = '\0'; // null-terminator
        printf("Password entered: %s\n", recieve_password_buffer);
        printf("recieved %d bytes\n", password_bytes_recieved);
      }
      else
      {
        fprintf(stderr, "recv() error: %s\n", gai_strerror(-1));
        exit(1);
      }

      sp = getspnam(recieve_login_buffer);  // find the line in shadow file by login

      if (sp != NULL)
      {
        full_encrypted_pass = sp->sp_pwdp;  // put encrypted password ($id$salt$hash) from that line on variable
        printf("%s\n", full_encrypted_pass); // printf it

        if (strcmp(crypt(recieve_password_buffer, full_encrypted_pass), full_encrypted_pass) == 0) // if encrypted recieved password with salt equals salt
        {
          password_and_login_are_correct = 1; // "boolean" variable for checking recieves value "true"

          sending_msg = "Welcome home.\n"; // same thing [2]
          send(new_sck, sending_msg, strlen(sending_msg), 0);
          memset(&sending_msg, 0, sizeof sending_msg);

          pw = getpwnam(recieve_login_buffer);
        }
        else
        {
          sending_msg = "Incorrect login and password. Please, try again.\n"; // same thing [2]
          send(new_sck, sending_msg, strlen(sending_msg), 0);
          memset(&sending_msg, 0, sizeof sending_msg);
        }
      }
      else
      {
        sending_msg = "Incorrect login and password. Please, try again.\n"; // same thing [2]
        send(new_sck, sending_msg, strlen(sending_msg), 0);
        memset(&sending_msg, 0, sizeof sending_msg);
      }

      memset(&recieve_login_buffer, 0, sizeof recieve_login_buffer); // free the buffer for login...
      memset(&recieve_password_buffer, 0, sizeof recieve_password_buffer); // ...and for password...
      memset(&full_encrypted_pass, 0, sizeof full_encrypted_pass); // ...and also for encrypted password
    }

    // After the successful authorisation we are leaving the cycle. This journey is going to be perfect.

    char *current_directory;
    char *client_login;

    current_directory = pw->pw_dir;
    client_login = pw->pw_name;

    char recieved_command[100];

    int command_bytes_recieved;

    // sending_msg = strcat(strcat(client_login, ":"), strcat(current_directory, "# "));
    sending_msg = malloc(200);
    strcat(sending_msg, client_login);
    strcat(sending_msg, ":");
    strcat(sending_msg, current_directory);
    strcat(sending_msg, "# ");

    printf ("client_login: %s\n", client_login);
    printf ("current_directory: %s\n", current_directory);

    char *unknown_command_alert = "Unknown command. Please, try again.\n";
    char *goodbye_alert = "Goodbye. \n";

    char *cat_no_args_error = "No args entered in cat command.\n";
    char *cat_no_such_file = "No such file. \n";
    char *cat_catalog = "Can't open: it's a catalog. \n";
    char *cat_not_a_file = "Can't open: it's not a usual file. \n";

    char *cd_no_args_error = "No args entered in cd command.\n";
    char *cd_not_a_catalog = "Can't move: it's not a catalog. \n";
    char *cd_no_such_catalog = "Can't move: no such catalog. \n";

    struct stat file_info;
    memset(&file_info, 0, sizeof file_info);

    while (strcmp(recieved_command, "exit") != 0)
    {
      memset(&recieved_command, 0, sizeof recieved_command);

      send(new_sck, sending_msg, strlen(sending_msg), 0);

      command_bytes_recieved = recv(new_sck, &recieved_command, sizeof recieved_command, 0);  // recv() the password from client to second buffer
      if (command_bytes_recieved > 2 && command_bytes_recieved < 99) // if it longer than 0 and shorter than 7
      {
        recieved_command[command_bytes_recieved - 2] = '\0'; // null-terminator
        printf("command entered: %s\n", recieved_command);
        printf("recieved %d bytes\n", command_bytes_recieved);

        if (strcmp(recieved_command, "ls") == 0)
        {

        }
        else if (recieved_command[0] == 'c' && recieved_command[1] == 'a' && recieved_command[2] == 't') // if client sends "cat"
        {
            if (recieved_command[3] == ' ') // if third symbol is ' '
            {
              char temp_dir[command_bytes_recieved]; // make temporary variable for recieved directory
              memset(temp_dir, 0, strlen(temp_dir)); // check if it isn't null

              int i = 4;
              while (recieved_command[i] != '\0') // fill temporary variable
              {
                temp_dir[i - 4] = recieved_command[i];
                i++;
              }
              temp_dir[i - 4] = '\0';

              printf("%s\n", temp_dir);

              if (temp_dir[0] == '/') // if zero symbol is /
              {
                // if fourth element of recieved_command equals /
                  // check if it's a common file
                  // then open() file by full path

                  if (stat(temp_dir, &file_info) >= 0) // get the stat structure (info about the file)
                  {
                    if (S_ISDIR(file_info.st_mode)) // if it is a catalog
                    {
                      send(new_sck, cat_catalog, strlen(cat_catalog), 0);
                    }
                    else if (S_ISREG(file_info.st_mode)) // if it's a usual file
                    {
                      // create a file descriptor, open file and send content to client
                      char *read_file_buffer = malloc(200);

                      int temp_fd = open(temp_dir, O_RDONLY);
                      if (temp_fd != -1)
                      {
                        if (read(temp_fd, read_file_buffer, 200) != -1)
                        {
                          send(new_sck, read_file_buffer, strlen(read_file_buffer), 0);
                        }

                        close(temp_fd);
                      }
                      else
                      {
                        send(new_sck, cat_no_such_file, strlen(cat_no_such_file), 0);
                      }
                    }
                    else
                    {
                      send(new_sck, cat_not_a_file, strlen(cat_not_a_file), 0);
                    }
                  }
                  else // if stat() returned a value below 0 (failed)
                  {
                    send(new_sck, cat_no_such_file, strlen(cat_no_such_file), 0);
                  }
              }
              else if (temp_dir[0] == '\0') // if temp_dir is empty
              {
                send(new_sck, cat_no_args_error, strlen(cat_no_args_error), 0);
              }
              else // if temp_dir isn't starts from /
              {
                // else
                  // check if it's a common file
                  // then open() file by current_directory + entered data after "cat "

                  char *temp_dir_full = malloc(200);

                  // temp_dir_full = strcat(current_directory, temp_dir);
                  strcat(temp_dir_full, current_directory);
                  strcat(temp_dir_full, "/");
                  strcat(temp_dir_full, temp_dir);

                  printf("%s\n", temp_dir_full);

                  if (stat(temp_dir_full, &file_info) >= 0) // get the stat structure (info about the file)
                  {
                    if (S_ISDIR(file_info.st_mode)) // if it is a catalog
                    {
                      send(new_sck, cat_catalog, strlen(cat_catalog), 0);
                    }
                    else if (S_ISREG(file_info.st_mode)) // if it's a usual file
                    {
                      // create a file descriptor, open file and send content to client
                      char *read_file_buffer = malloc(200);

                      int temp_fd = open(temp_dir_full, O_RDONLY);
                      if (temp_fd != -1)
                      {
                        if (read(temp_fd, read_file_buffer, 200) != -1)
                        {
                          send(new_sck, read_file_buffer, strlen(read_file_buffer), 0);
                        }

                        close(temp_fd);
                      }
                      else
                      {
                        send(new_sck, cat_no_such_file, strlen(cat_no_such_file), 0);
                      }
                    }
                    else
                    {
                      send(new_sck, cat_not_a_file, strlen(cat_not_a_file), 0);
                    }
                  }
                  else // if stat() returned a value below 0 (failed)
                  {
                    send(new_sck, cat_no_such_file, strlen(cat_no_such_file), 0);
                  }
              }
            }
            else if (recieved_command[3] == '\0') // if recieved_command equals "cat" without args
            {
              send(new_sck, cat_no_args_error, strlen(cat_no_args_error), 0);
            }
        }
        else if (recieved_command[0] == 'c' && recieved_command[1] == 'd') // if client sends "cd"
        {
            if (recieved_command[2] == ' ') // if second symbol is ' '
            {
              char temp_dir[command_bytes_recieved]; // make temporary variable for recieved directory
              memset(temp_dir, 0, strlen(temp_dir)); // check if it isn't null

              int i = 3;
              while (recieved_command[i] != '\0') // fill temporary variable
              {
                temp_dir[i - 3] = recieved_command[i];
                i++;
              }
              temp_dir[i - 3] = '\0';

              printf("%s\n", temp_dir);

              if (temp_dir[0] == '/') // if zero symbol is /
              {
                // if third element of recieved_command equals /
                  // check if it's a catalog
                  // then change current_directory to that path

                  if (stat(temp_dir, &file_info) >= 0) // get the stat structure (info about the file)
                  {
                    if (S_ISDIR(file_info.st_mode)) // if it is a catalog
                    {
                      // change current_directory to temp_dir
                      memset(current_directory, 0, sizeof current_directory);
                      strcat(current_directory, temp_dir);

                      memset(sending_msg, 0, sizeof sending_msg);
                      strcat(sending_msg, client_login);
                      strcat(sending_msg, ":");
                      strcat(sending_msg, current_directory);
                      strcat(sending_msg, "# ");

                    }
                    else // if it isn't a catalog
                    {
                      send(new_sck, cd_not_a_catalog, strlen(cd_not_a_catalog), 0);
                    }
                  }
                  else // if stat() returned a value below 0 (failed)
                  {
                    send(new_sck, cd_no_such_catalog, strlen(cd_no_such_catalog), 0);
                  }
              }
              else if (temp_dir[0] == '\0') // if temp_dir is empty
              {
                send(new_sck, cd_no_args_error, strlen(cd_no_args_error), 0);
              }
              else // if temp_dir isn't starts from /
              {
                // else
                  // check if it's a catalog
                  // then change the current_directory to temp_dir_full

                  char *temp_dir_full = malloc(200);

                  // temp_dir_full = strcat(current_directory, temp_dir);
                  strcat(temp_dir_full, current_directory);
                  if (strcmp(current_directory, "/") != 0)
                  {
                    strcat(temp_dir_full, "/");
                  }
                  strcat(temp_dir_full, temp_dir);

                  printf("%s\n", temp_dir_full);

                  if (stat(temp_dir_full, &file_info) >= 0) // get the stat structure (info about the file)
                  {
                    if (S_ISDIR(file_info.st_mode)) // if it is a catalog
                    {
                      memset(current_directory, 0, sizeof current_directory);
                      strcat(current_directory, temp_dir_full);

                      memset(sending_msg, 0, sizeof sending_msg);
                      strcat(sending_msg, client_login);
                      strcat(sending_msg, ":");
                      strcat(sending_msg, current_directory);
                      strcat(sending_msg, "# ");
                    }
                    else
                    {
                      send(new_sck, cd_not_a_catalog, strlen(cd_not_a_catalog), 0);
                    }
                  }
                  else // if stat() returned a value below 0 (failed)
                  {
                    send(new_sck, cd_no_such_catalog, strlen(cd_no_such_catalog), 0);
                  }
              }
            }
            else if (recieved_command[2] == '\0')
            {
              send(new_sck, cd_no_args_error, strlen(cd_no_args_error), 0);
            }
        }
        else if (strcmp(recieved_command, "exit") == 0)
        {
          send(new_sck, goodbye_alert, strlen(goodbye_alert), 0);
          close(new_sck);
        }
        else
        {
          send(new_sck, unknown_command_alert, strlen(unknown_command_alert), 0);
        }
      }
      else
      {
        send(new_sck, unknown_command_alert, strlen(unknown_command_alert), 0);
      }
    }
    memset(&recieved_command, 0, sizeof recieved_command);
  }
}

// entry point of programm
int main(int argc, char *argv[])
{
  e_gai(argv[1]);
  e_socket(full_info_strc->ai_family, full_info_strc->ai_socktype, full_info_strc->ai_protocol);
  e_bind(sck, full_info_strc->ai_addr, full_info_strc->ai_addrlen);
  e_listen(sck, 20);
  e_accept(sck);

  freeaddrinfo(full_info_strc);
}
