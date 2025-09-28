package repository

import (
	"fmt"
)

var (
	ErrUserNotFound      = fmt.Errorf("пользователь не найден")
	ErrUserAlreadyExists = fmt.Errorf("пользователь уже существует")
	ErrInvalidData       = fmt.Errorf("некорректные данные")
	ErrDatabaseError     = fmt.Errorf("ошибка базы данных")
)
