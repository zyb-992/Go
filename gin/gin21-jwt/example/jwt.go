package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

const sign_key = "zyb"

type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Myclaims struct {
	jwt.StandardClaims
	UserInfo
}

func main() {
	r := gin.Default()
	// 获取token
	r.POST("/auth", authHandler)

	// 直接从请求头发送token到服务端 通过中间件解析jwt
	r.GET("/home", JwtMiddleware(), homeHandler)
	r.Run(":9090")
}

func authHandler(c *gin.Context) {
	var user UserInfo
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusAccepted, gin.H{
			"code": 201,
			"msg":  "无效参数",
		})
		return
	}

	if user.Username == "zyb" && user.Password == "qq" {
		// 用户登录成功 生成对应token返回
		tokenString := GenToken(user)
		c.JSON(http.StatusOK, gin.H{
			"code": 200,
			"msg":  "Login Success",
			"data": gin.H{
				"token": tokenString,
			},
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"code": 201,
		"msg":  "鉴权失败",
	})

}
func GenToken(user UserInfo) string {
	claims := Myclaims{
		jwt.StandardClaims{
			// 什么时间开始生效
			NotBefore: time.Now().Unix() - 60,
			// 什么时间过期
			ExpiresAt: time.Now().Unix() + 60*60*2,
			Issuer:    "zyb",
		},
		user,
	}
	g_token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	mySigningKey := []byte(sign_key)
	sign_g_token, err := g_token.SignedString(mySigningKey)
	if err != nil {
		fmt.Println("Signed Error")
	}
	return sign_g_token
}

func JwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("xtoken")
		if authHeader == "" {
			c.JSON(http.StatusOK, gin.H{
				"code": 2003,
				"msg":  "请求头中auth为空",
			})
			c.Abort()
			return
		}

		// 直接解析token即可 不用分段
		mc, err := jwt.ParseWithClaims(authHeader, &Myclaims{}, func(token *jwt.Token) (interface{}, error) {
			// sign_key是签名 解密token
			return []byte(sign_key), nil
		})
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 2005,
				"msg":  "无效token",
			})
			c.Abort()
			return
		}
		c.Set("username", mc.Claims.(*Myclaims).UserInfo.Username)
		c.Next()
	}
}
func homeHandler(c *gin.Context) {
	username := c.MustGet("username").(string)
	c.JSON(http.StatusOK, gin.H{
		"code": 2000,
		"msg":  "success",
		"data": gin.H{"username": username},
	})
}
