import fs from 'fs/promises'
import path from 'path'
import { log } from './logger.mjs'

/**
 * Generate a main wrapper file for a circuit
 * @param {string} circuitName - Name of the circuit
 * @param {object} circuitConfig - Circuit configuration from circuits.json
 * @param {string} projectDir - Project root directory
 */
export async function generateMain(circuitName, circuitConfig, projectDir) {
    const { file, template, params } = circuitConfig

    // Generate the main wrapper content
    const paramsStr = params ? params.join(', ') : ''
    const content = `pragma circom 2.0.0;

include "../${file}.circom";

component main = ${template}(${paramsStr});
`

    // Write the file
    const mainDir = path.join(projectDir, 'circuits', 'main')
    await fs.mkdir(mainDir, { recursive: true })
    
    const outputPath = path.join(mainDir, `${circuitName}.circom`)
    await fs.writeFile(outputPath, content, 'utf-8')
    
    log.success(`Generated main wrapper: ${outputPath}`)
    
    return outputPath
}

