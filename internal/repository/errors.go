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

var (
	ErrSessionNotFound = fmt.Errorf("сессия не найдена")
	ErrAlreadyUsed     = fmt.Errorf("refresh уже использован")
)
