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
#include "main.h"
#include "chacha20.h"
#include <string.h>

/* Private user code ---------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
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
  /* Reset of all peripherals, Initializes the Systick */
  HAL_Init();

  int ret = TestEncryptDecrypt();
  if (ret != 0) {
    while (1);
  }

  while (1) {
    BSP_LED_On(LED_GREEN);
    HAL_Delay(1000);
    BSP_LED_Off(LED_GREEN);
    HAL_Delay(1000);
  }
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
