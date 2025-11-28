/**
 ******************************************************************************
 * @file    main.c
 * @author  MCU Application Team
 * @brief   Main program body
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2023 Puya Semiconductor Co.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by Puya under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2016 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 ******************************************************************************
 */

/* Includes ------------------------------------------------------------------*/
#include <string.h>
#include "main.h"
#include "py32f003xx_ll_Start_Kit.h"
#include "chacha20.h"

/* Private define ------------------------------------------------------------*/
#define LED_GPIO_PIN          LED3_PIN
#define LED_GPIO_PORT         LED3_GPIO_PORT
#define LED_GPIO_CLK_ENABLE() LED3_GPIO_CLK_ENABLE()

/* Private variables ---------------------------------------------------------*/
/* Private user code ---------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
static void APP_SystemClockConfig(void);
static void APP_GpioConfig(void);
static int TestEncryptDecrypt();

static int TestEncryptDecrypt()
{
  uint8_t key[CHACHA20_KEY_SIZE], nonce[CHACHA20_NONCE_SIZE];
  chacha20_keygen(key);     // Generate random key
  chacha20_noncegen(nonce); // Generate random nonce

  // Initialize
  chacha20_ctx *ctx = chacha20_new();
  chacha20_init(ctx, key, nonce, 1);

  // Encrypt/Decrypt (symmetric operation)
  char plaintext[] = "Hello, World!";
  uint8_t ciphertext[sizeof(plaintext)];
  chacha20_encrypt(ctx, (uint8_t *)plaintext, ciphertext, sizeof(plaintext));

  char origintext[20];
  memset(origintext, 0, sizeof(origintext));
  chacha20_init(ctx, key, nonce, 1);
  chacha20_decrypt(ctx, ciphertext, (uint8_t *)origintext, sizeof(ciphertext));

  // Cleanup
  chacha20_clear(ctx);
  chacha20_free(ctx);

  int ret = strcmp(plaintext, origintext);
  return ret;
}

/**
 * @brief  Main program.
 * @retval int
 */
int main(void)
{
  /* Configure system clock */
  APP_SystemClockConfig();

  /* Initialize GPIO */
  APP_GpioConfig();

  int ret = TestEncryptDecrypt();
  if (ret != 0) {
    while (1);
  }

  while (1) {
    /* LED blinking */
    LL_mDelay(1000);
    LL_GPIO_TogglePin(LED_GPIO_PORT, LED_GPIO_PIN);
  }
}

/**
 * @brief  Configure system clock
 * @param  None
 * @retval None
 */
static void APP_SystemClockConfig(void)
{
  /* Enable HSI */
  LL_RCC_HSI_Enable();
  while (LL_RCC_HSI_IsReady() != 1) {
  }

  /* Set AHB prescaler*/
  LL_RCC_SetAHBPrescaler(LL_RCC_SYSCLK_DIV_1);

  /* Configure HSISYS as system clock source */
  LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_HSISYS);
  while (LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_HSISYS) {
  }

  /* Set APB1 prescaler*/
  LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);
  LL_Init1msTick(8000000);

  /* Update system clock global variable SystemCoreClock (can also be updated by calling SystemCoreClockUpdate function) */
  LL_SetSystemCoreClock(8000000);
}

/**
 * @brief  GPIO configuration function
 * @param  None
 * @retval None
 */
static void APP_GpioConfig(void)
{
  /* Enable clock */
  LED_GPIO_CLK_ENABLE();

  /* Configure LED pin as output */
  LL_GPIO_SetPinMode(LED_GPIO_PORT, LED_GPIO_PIN, LL_GPIO_MODE_OUTPUT);
  /* Default (after reset) is push-pull output */
  /* LL_GPIO_SetPinOutputType(LED_GPIO_PORT, LED_GPIO_PIN, LL_GPIO_OUTPUT_PUSHPULL); */
  /* Default (after reset) is very low output speed */
  /* LL_GPIO_SetPinSpeed(LED_GPIO_PORT, LED_GPIO_PIN, LL_GPIO_SPEED_FREQ_LOW); */
  /* Default (after reset) is no pull-up or pull-down */
  /* LL_GPIO_SetPinPull(LED_GPIO_PORT, LED_GPIO_PIN, LL_GPIO_PULL_NO); */
}

/**
 * @brief  This function is executed in case of error occurrence.
 * @param  None
 * @retval None
 */
void APP_ErrorHandler(void)
{
  /* infinite loop */
  while (1) {
  }
}

#ifdef USE_FULL_ASSERT
/**
 * @brief  Reports the name of the source file and the source line number
 *         where the assert_param error has occurred.
 * @param  file: pointer to the source file name
 * @retval None
 */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* User can add his own implementation to report the file name and line number,
     for example: printf("Wrong parameters value: file %s on line %d\r\n", file, line)  */
  /* infinite loop */
  while (1) {
  }
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT Puya *****END OF FILE******************/
