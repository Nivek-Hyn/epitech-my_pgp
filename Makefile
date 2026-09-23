##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## Makefile
##

NAME	=	my_pgp

all:	$(NAME)

$(NAME):
	@echo '#!/usr/bin/env python3' > $(NAME)
	@cat main.py >> $(NAME)
	@chmod +x $(NAME)

clean:
	@rm -rf __pycache__

fclean:	clean
	@rm -f $(NAME)

re:	fclean all

.PHONY:	all clean fclean re
